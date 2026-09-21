using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
namespace Wela.FailedLogonProbe {
 public sealed class Attempt {
  public string UserName, Domain, StartedUtc, CompletedUtc, Clock;
  public int MissingAccountStatus, LogonType, LogonProvider, NativeError;
  public bool Succeeded;
 }
 public static class Native {
  [DllImport("kernel32.dll", ExactSpelling=true)] private static extern void GetSystemTimePreciseAsFileTime(out long value);
  [DllImport("Netapi32.dll", CharSet=CharSet.Unicode, ExactSpelling=true)] private static extern int NetUserGetInfo(string server,string user,int level,out IntPtr buffer);
  [DllImport("Netapi32.dll", ExactSpelling=true)] private static extern int NetApiBufferFree(IntPtr buffer);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, ExactSpelling=true, SetLastError=true)]
  [return:MarshalAs(UnmanagedType.Bool)] private static extern bool LogonUserW(string user,string domain,string password,int type,int provider,out IntPtr token);
  [DllImport("kernel32.dll", ExactSpelling=true, SetLastError=true)]
  [return:MarshalAs(UnmanagedType.Bool)] private static extern bool CloseHandle(IntPtr handle);
  public static DateTime UtcNow(){long value;GetSystemTimePreciseAsFileTime(out value);return DateTime.FromFileTimeUtc(value);}
  public static Attempt Run(string nonce){
   if(!Regex.IsMatch(nonce??"","\\A[a-f0-9]{32}\\z"))throw new ArgumentException("A generated lowercase GUID nonce is required.");
   string user="WL"+nonce.Substring(0,18);IntPtr buffer=IntPtr.Zero;
   int missing;
   try{missing=NetUserGetInfo(null,user,0,out buffer);}finally{if(buffer!=IntPtr.Zero)NetApiBufferFree(buffer);}
   // Never attempt a known or unreadable real account, and never query a domain server.
   if(missing!=2221)throw new InvalidOperationException("Exact local account absence is not established; NetUserGetInfo="+missing);
   Attempt result=new Attempt();result.UserName=user;result.Domain=".";result.MissingAccountStatus=missing;result.LogonType=3;result.LogonProvider=2;result.Clock="GetSystemTimePreciseAsFileTime";
   IntPtr token=IntPtr.Zero;
   result.StartedUtc=UtcNow().ToString("o");
   try{
    // This fixed public dummy is not a credential. There is exactly one attempt.
    result.Succeeded=LogonUserW(user,".","WELA-public-noncredential",3,2,out token);
    result.NativeError=result.Succeeded?0:Marshal.GetLastWin32Error();
    result.CompletedUtc=UtcNow().ToString("o");
   }finally{if(token!=IntPtr.Zero && !CloseHandle(token))throw new Win32Exception(Marshal.GetLastWin32Error());}
   return result;
  }
 }
}
