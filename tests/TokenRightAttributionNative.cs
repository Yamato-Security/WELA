using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace Wela.TokenRightProbe {
 public sealed class Privilege { public string Luid; public uint Attributes; }
 public sealed class Outcome {
  public string Status, Diagnostic, Luid;
  public bool AdjustmentAttempted, Restored;
  public uint OriginalAttributes;
  public long DisableStartedFileTime, DisableReturnedFileTime, RestoreStartedFileTime, RestoreReturnedFileTime, PrivilegeVerificationCompletedFileTime, OperationCompletedFileTime;
  public Privilege[] Before, Disabled, After;
 }
 public static class Native {
  [StructLayout(LayoutKind.Sequential)] struct Luid { public uint Low; public int High; }
  [StructLayout(LayoutKind.Sequential)] struct Entry { public Luid Id; public uint Attributes; }
  [StructLayout(LayoutKind.Sequential)] struct One { public uint Count; public Luid Id; public uint Attributes; }
  [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
  [DllImport("kernel32.dll")] static extern IntPtr GetCurrentThread();
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
  [DllImport("kernel32.dll")] static extern void GetSystemTimePreciseAsFileTime(out long value);
  [DllImport("kernel32.dll")] static extern void SetLastError(uint error);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool QueryFullProcessImageName(IntPtr process,uint flags,StringBuilder path,ref uint length);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenThreadToken(IntPtr thread,uint access,bool self,out IntPtr token);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetTokenInformation(IntPtr token,int kind,IntPtr buffer,int length,out int needed);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool LookupPrivilegeValue(string system,string name,out Luid value);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool AdjustTokenPrivileges(IntPtr token,bool all,ref One value,uint length,IntPtr previous,IntPtr returned);
  static string Hex(Luid id) { return "0x"+(((ulong)(uint)id.High<<32)|id.Low).ToString("x"); }
  static long Now() { long value; GetSystemTimePreciseAsFileTime(out value); return value; }
  public static string Executable() {
   var path=new StringBuilder(32768);uint length=32768;
   if(!QueryFullProcessImageName(GetCurrentProcess(),0,path,ref length)||length<1||length>=32768)throw new Win32Exception(Marshal.GetLastWin32Error());
   return path.ToString();
  }
  static void PrimaryOnly() {
   IntPtr thread;
   if(OpenThreadToken(GetCurrentThread(),8,true,out thread)) { CloseHandle(thread); throw new InvalidOperationException("An impersonation token is not accepted."); }
   int error=Marshal.GetLastWin32Error();
   if(error!=1008) throw new Win32Exception(error,"Cannot establish absence of an impersonation token.");
  }
  static Privilege[] Read(IntPtr token) {
   int needed; bool first=GetTokenInformation(token,3,IntPtr.Zero,0,out needed); int error=Marshal.GetLastWin32Error();
   if(first||error!=122||needed<4||needed>65536) throw new InvalidOperationException("Unexpected token privilege size response.");
   IntPtr buffer=Marshal.AllocHGlobal(needed);
   try {
    int returned;
    if(!GetTokenInformation(token,3,buffer,needed,out returned))throw new Win32Exception(Marshal.GetLastWin32Error());
    int count=Marshal.ReadInt32(buffer); int size=Marshal.SizeOf(typeof(Entry));
    if(returned>needed||count<1||count>4096||4L+(long)count*size>returned)throw new InvalidOperationException("Truncated token privileges.");
    var result=new List<Privilege>(); var seen=new HashSet<string>(StringComparer.Ordinal);
    for(int i=0;i<count;i++) { var item=(Entry)Marshal.PtrToStructure(IntPtr.Add(buffer,4+i*size),typeof(Entry)); string id=Hex(item.Id); if(!seen.Add(id))throw new InvalidOperationException("Duplicate token privilege."); result.Add(new Privilege{Luid=id,Attributes=item.Attributes}); }
    result.Sort((a,b)=>String.CompareOrdinal(a.Luid,b.Luid));return result.ToArray();
   } finally { Marshal.FreeHGlobal(buffer); }
  }
  static void Change(IntPtr token,Luid id,uint attributes) {
   var value=new One{Count=1,Id=id,Attributes=attributes};SetLastError(0);
   bool ok=AdjustTokenPrivileges(token,false,ref value,0,IntPtr.Zero,IntPtr.Zero);int error=Marshal.GetLastWin32Error();
   if(!ok||error!=0)throw new Win32Exception(error,"The fixed privilege adjustment did not report complete success.");
  }
  static void Equal(Privilege[] expected,Privilege[] actual,string changed,bool enabled) {
   if(expected==null||actual==null||expected.Length!=actual.Length)throw new InvalidOperationException("Privilege inventory changed.");
   for(int i=0;i<expected.Length;i++) {
    uint attributes=expected[i].Attributes;
    if(expected[i].Luid==changed&&!enabled)attributes&=~2U;
    if(expected[i].Luid!=actual[i].Luid||attributes!=actual[i].Attributes)throw new InvalidOperationException("Unexpected token privilege state.");
   }
  }
  public static Outcome Run() {
   var result=new Outcome{Status="Refused",Diagnostic=""};IntPtr token=IntPtr.Zero;Luid target=new Luid();
   try {
    PrimaryOnly();
    if(!OpenProcessToken(GetCurrentProcess(),0x28,out token))throw new Win32Exception(Marshal.GetLastWin32Error());
    if(!LookupPrivilegeValue(null,"SeDebugPrivilege",out target))throw new Win32Exception(Marshal.GetLastWin32Error());
    result.Luid=Hex(target);result.Before=Read(token);Privilege found=null;
    foreach(var item in result.Before)if(item.Luid==result.Luid)found=item;
    if(found==null||(found.Attributes&2)==0||(found.Attributes&4)!=0)throw new InvalidOperationException("SeDebugPrivilege must already be present and enabled; no new privilege is granted.");
    result.OriginalAttributes=found.Attributes;
    try {
     result.DisableStartedFileTime=Now();result.AdjustmentAttempted=true;
     Change(token,target,found.Attributes&~2U);result.DisableReturnedFileTime=Now();
     result.Disabled=Read(token);Equal(result.Before,result.Disabled,result.Luid,false);
     result.Status="Adjusted";
    } finally {
     if(result.AdjustmentAttempted) {
      result.RestoreStartedFileTime=Now();Change(token,target,result.OriginalAttributes);result.RestoreReturnedFileTime=Now();
      result.After=Read(token);Equal(result.Before,result.After,result.Luid,true);result.Restored=true;result.PrivilegeVerificationCompletedFileTime=Now();result.OperationCompletedFileTime=result.PrivilegeVerificationCompletedFileTime;
     }
    }
   } catch(Exception error) {result.Status=result.AdjustmentAttempted?"Unverified":"Refused";result.Diagnostic=error.ToString();}
   finally {if(token!=IntPtr.Zero)CloseHandle(token);}
   return result;
  }
 }
}
