// Handle-bound local file/registry SACL reads and additive audit writes only.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
namespace Wela.SelectedSacl {
 public sealed class Ace {
  public string Binary; public int Type; public int Flags; public int Mask; public string Sid; public bool Ordinary;
 }
 public sealed class Snapshot {
  public string Path; public string Kind; public string Identity; public bool IsDirectory;
  public string DescriptorBase64; public string Owner; public string Group; public string DaclBase64;
  public int ControlFlags; public Ace[] Aces;
 }
 public sealed class Privilege : IDisposable {
  [StructLayout(LayoutKind.Sequential)] struct Luid { public uint Low; public int High; }
  [StructLayout(LayoutKind.Sequential)] struct TokenPrivileges { public uint Count; public Luid Luid; public uint Attributes; }
  [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
  [DllImport("kernel32.dll")] static extern IntPtr GetCurrentThread();
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr value);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenThreadToken(IntPtr thread,uint access,bool self,out IntPtr token);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool LookupPrivilegeValue(string system,string name,out Luid luid);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool AdjustTokenPrivileges(IntPtr token,bool disable,ref TokenPrivileges value,uint size,out TokenPrivileges previous,out uint required);
  IntPtr token; TokenPrivileges previous;
  public Privilege() {
   IntPtr threadToken;
   if(OpenThreadToken(GetCurrentThread(),8,true,out threadToken)) {CloseHandle(threadToken);throw new InvalidOperationException("Impersonated callers are outside the selected-SACL workflow.");}
   int error=Marshal.GetLastWin32Error();if(error!=1008)throw new Win32Exception(error,"Cannot establish absence of an impersonation token.");
   if(!OpenProcessToken(GetCurrentProcess(),0x28,out token))throw new Win32Exception(Marshal.GetLastWin32Error());
   try {
    Luid luid;if(!LookupPrivilegeValue(null,"SeSecurityPrivilege",out luid))throw new Win32Exception(Marshal.GetLastWin32Error());
    TokenPrivileges requested=new TokenPrivileges {Count=1,Luid=luid,Attributes=2};uint required;
    bool ok=AdjustTokenPrivileges(token,false,ref requested,(uint)Marshal.SizeOf(typeof(TokenPrivileges)),out previous,out required);
    error=Marshal.GetLastWin32Error();if(!ok||error!=0)throw new Win32Exception(error,"SeSecurityPrivilege is not available.");
   }catch {CloseHandle(token);token=IntPtr.Zero;throw;}
  }
  public void Dispose() {
   if(token==IntPtr.Zero)return;
   try {TokenPrivileges ignored;uint required;bool ok=AdjustTokenPrivileges(token,false,ref previous,(uint)Marshal.SizeOf(typeof(TokenPrivileges)),out ignored,out required);int error=Marshal.GetLastWin32Error();if(!ok||error!=0)throw new Win32Exception(error,"SeSecurityPrivilege restoration failed.");}
   finally {CloseHandle(token);token=IntPtr.Zero;}
  }
 }
 public sealed class Target : IDisposable {
  [StructLayout(LayoutKind.Sequential,Pack=4)] struct FileInfo {public uint Attributes;public long Created;public long Accessed;public long Written;public uint Volume;public uint SizeHigh;public uint SizeLow;public uint Links;public uint IndexHigh;public uint IndexLow;}
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateFile(string name,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr value);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(IntPtr handle,out FileInfo information);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern uint GetFinalPathNameByHandle(IntPtr handle,StringBuilder path,uint size,uint flags);
  [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr value);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode)] static extern int RegOpenKeyEx(IntPtr key,string path,uint options,uint access,out IntPtr opened);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode)] static extern int RegQueryValueEx(IntPtr key,string name,IntPtr reserved,out uint type,IntPtr data,ref uint size);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode)] static extern int RegQueryInfoKey(IntPtr key,IntPtr cls,IntPtr clsSize,IntPtr reserved,IntPtr subKeys,IntPtr maxSubKey,IntPtr maxClass,IntPtr values,IntPtr maxValueName,IntPtr maxValue,IntPtr securitySize,out long written);
  [DllImport("advapi32.dll")] static extern int RegCloseKey(IntPtr key);
  [DllImport("advapi32.dll")] static extern uint GetSecurityInfo(IntPtr handle,uint kind,uint flags,out IntPtr owner,out IntPtr group,out IntPtr dacl,out IntPtr sacl,out IntPtr descriptor);
  [DllImport("advapi32.dll")] static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
  [DllImport("advapi32.dll")] static extern uint SetSecurityInfo(IntPtr handle,uint kind,uint flags,IntPtr owner,IntPtr group,IntPtr dacl,IntPtr sacl);
  IntPtr handle;readonly List<IntPtr> keys=new List<IntPtr>();readonly string path;readonly string kind;readonly uint objectType;
  public Target(string kind,string path) {
   this.kind=kind;this.path=path;objectType=kind=="FileSystem"?1U:4U;
   try {
    if(kind=="FileSystem") {
     // No DELETE sharing: keep the opened object stable while reading/writing it.
     handle=CreateFile(path,0x01020000,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero);
     if(handle==new IntPtr(-1)){handle=IntPtr.Zero;throw new Win32Exception(Marshal.GetLastWin32Error());}
     FileInfo info;if(!GetFileInformationByHandle(handle,out info))throw new Win32Exception(Marshal.GetLastWin32Error());
     if((info.Attributes&0x400)!=0)throw new InvalidOperationException("Reparse-point file target refused.");
     StringBuilder final=new StringBuilder(32768);uint length=GetFinalPathNameByHandle(handle,final,(uint)final.Capacity,0);
     if(length==0||length>=final.Capacity)throw new InvalidOperationException("Cannot verify final local file path.");
     if(!String.Equals(final.ToString(),"\\\\?\\"+path,StringComparison.OrdinalIgnoreCase))throw new InvalidOperationException("Final handle path differs from selected path (link/redirection).");
    } else if(kind=="Registry") {
     string[] parts=path.Split('\\');IntPtr current;
     if(parts[0]=="HKEY_LOCAL_MACHINE")current=new IntPtr(unchecked((int)0x80000002));
     else if(parts[0]=="HKEY_USERS")current=new IntPtr(unchecked((int)0x80000003));
     else throw new InvalidOperationException("Only explicitly selected HKLM/HKU keys are supported.");
     if(parts.Length<2)throw new InvalidOperationException("A registry hive root cannot be selected.");
     for(int i=1;i<parts.Length;i++) {
      IntPtr opened;int error=RegOpenKeyEx(current,parts[i],8,0x01020101,out opened); // OPEN_LINK, 64-bit view, query/read-control/SACL.
      if(error!=0)throw new Win32Exception(error);keys.Add(opened);current=opened;
      uint type;uint size=0;error=RegQueryValueEx(current,"SymbolicLinkValue",IntPtr.Zero,out type,IntPtr.Zero,ref size);
      if(error==0&&type==6)throw new InvalidOperationException("Registry symbolic-link component refused.");
      if(error!=0&&error!=2)throw new Win32Exception(error,"Registry link state is unreadable.");
     }
     handle=current;
    } else throw new InvalidOperationException("Unsupported selected target kind.");
   }catch {Dispose();throw;}
  }
  static string Bytes(GenericAcl acl){if(acl==null)return null;byte[] bytes=new byte[acl.BinaryLength];acl.GetBinaryForm(bytes,0);return Convert.ToBase64String(bytes);}
  static string Bytes(GenericAce ace){byte[] bytes=new byte[ace.BinaryLength];ace.GetBinaryForm(bytes,0);return Convert.ToBase64String(bytes);}
  public Snapshot Read() {
   if(handle==IntPtr.Zero)throw new ObjectDisposedException("Target");
   // BACKUP_SECURITY_INFORMATION reads every descriptor section, including labels/resource/CAP ACEs.
   IntPtr owner,group,dacl,sacl,descriptor;uint error=GetSecurityInfo(handle,objectType,0x00010000,out owner,out group,out dacl,out sacl,out descriptor);
   if(error!=0) {
    // Read-only diagnostics retain the failure; never substitute a partial descriptor.
    StringBuilder detail=new StringBuilder("GetSecurityInfo BACKUP failed for "+kind+" ("+error+"). Section query results:");
    foreach(uint requested in new uint[] {1,4,8,16,32,64,128,256,31,511}) {
     IntPtr o,g,d,a,probeDescriptor;uint result=GetSecurityInfo(handle,objectType,requested,out o,out g,out d,out a,out probeDescriptor);
     if(result==0&&probeDescriptor!=IntPtr.Zero)LocalFree(probeDescriptor);detail.Append(" "+requested+"="+result);
    }
    throw new Win32Exception((int)error,detail.ToString());
   }
   byte[] bytes;
   try {uint length=GetSecurityDescriptorLength(descriptor);if(length<20||length>1048576)throw new InvalidOperationException("Invalid descriptor size.");bytes=new byte[length];Marshal.Copy(descriptor,bytes,0,(int)length);}
   finally {LocalFree(descriptor);}
   RawSecurityDescriptor sd=new RawSecurityDescriptor(bytes,0);List<Ace> entries=new List<Ace>();
   if(sd.SystemAcl!=null)foreach(GenericAce ace in sd.SystemAcl) {
    CommonAce common=ace as CommonAce;bool ordinary=common!=null&&!common.IsCallback&&common.AceType==AceType.SystemAudit;
    entries.Add(new Ace {Binary=Bytes(ace),Type=(int)ace.AceType,Flags=(int)ace.AceFlags,Mask=ordinary?common.AccessMask:0,Sid=ordinary?common.SecurityIdentifier.Value:null,Ordinary=ordinary});
   }
   string identity;bool directory=false;
   if(kind=="FileSystem") {FileInfo info;if(!GetFileInformationByHandle(handle,out info))throw new Win32Exception(Marshal.GetLastWin32Error());directory=(info.Attributes&16)!=0;identity=info.Volume+":"+info.IndexHigh+":"+info.IndexLow+":"+info.Created;}
   else {long written;int result=RegQueryInfoKey(handle,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,out written);if(result!=0)throw new Win32Exception(result);identity=path+":"+written;}
   return new Snapshot {Path=path,Kind=kind,Identity=identity,IsDirectory=directory,DescriptorBase64=Convert.ToBase64String(bytes),Owner=sd.Owner==null?null:sd.Owner.Value,Group=sd.Group==null?null:sd.Group.Value,DaclBase64=Bytes(sd.DiscretionaryAcl),ControlFlags=(int)sd.ControlFlags,Aces=entries.ToArray()};
  }
  public Snapshot Add(string expectedIdentity,string expectedDescriptor,string sid,int mask,int flags) {
   Snapshot before=Read();if(before.Identity!=expectedIdentity||before.DescriptorBase64!=expectedDescriptor)throw new InvalidOperationException("Target changed after the recovery snapshot.");
   if(mask<=0||(flags&~195)!=0||(flags&192)==0)throw new InvalidOperationException("Invalid selected audit ACE.");
   RawSecurityDescriptor sd=new RawSecurityDescriptor(Convert.FromBase64String(before.DescriptorBase64),0);
   RawAcl acl=sd.SystemAcl??new RawAcl(2,1);
   acl.InsertAce(acl.Count,new CommonAce((AceFlags)flags,AceQualifier.SystemAudit,mask,new SecurityIdentifier(sid),false,null));
   byte[] bytes=new byte[acl.BinaryLength];acl.GetBinaryForm(bytes,0);IntPtr buffer=Marshal.AllocHGlobal(bytes.Length);
   try {Marshal.Copy(bytes,0,buffer,bytes.Length);uint error=SetSecurityInfo(handle,objectType,8,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,buffer);if(error!=0)throw new Win32Exception((int)error);}
   finally {Marshal.FreeHGlobal(buffer);}
   return Read();
  }
  public void Dispose(){if(kind=="FileSystem"&&handle!=IntPtr.Zero)CloseHandle(handle);for(int i=keys.Count-1;i>=0;i--)RegCloseKey(keys[i]);keys.Clear();handle=IntPtr.Zero;}
 }
}
