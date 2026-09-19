// Disposable fixture setup only. Never loaded by WELA production commands.
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
namespace Wela.SelectedSaclFixture {
 public static class Protection {
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateFile(string name,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode)] static extern int RegOpenKeyEx(IntPtr parent,string name,uint options,uint access,out IntPtr handle);
  [DllImport("advapi32.dll")] static extern int RegCloseKey(IntPtr key);
  [DllImport("advapi32.dll")] static extern uint SetSecurityInfo(IntPtr handle,uint kind,uint flags,IntPtr owner,IntPtr group,IntPtr dacl,IntPtr sacl);
  public static void Protect(string kind,string path,string descriptor,string nonce) {
   if(Environment.GetEnvironmentVariable("GITHUB_ACTIONS")!="true"||Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT")!="github-hosted"||String.IsNullOrEmpty(nonce)||nonce.Length!=32||!path.Contains(nonce)||!path.EndsWith("\\protected",StringComparison.OrdinalIgnoreCase))throw new InvalidOperationException("Only explicitly owned disposable protected fixture objects are accepted.");
   IntPtr handle=IntPtr.Zero,buffer=IntPtr.Zero;bool registry=kind=="Registry";
   try {
    if(registry) {
     if(!path.StartsWith("HKEY_USERS\\",StringComparison.Ordinal))throw new InvalidOperationException("Fixture must use its current HKU identity.");
     int error=RegOpenKeyEx(new IntPtr(unchecked((int)0x80000003)),path.Substring(11),8,0x01000100,out handle);
     if(error!=0)throw new Win32Exception(error);
    } else {
     if(kind!="FileSystem")throw new InvalidOperationException("Unknown fixture kind.");
     handle=CreateFile(path,0x01000000,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero);
     if(handle==new IntPtr(-1)){handle=IntPtr.Zero;throw new Win32Exception(Marshal.GetLastWin32Error());}
    }
    RawSecurityDescriptor sd=new RawSecurityDescriptor(Convert.FromBase64String(descriptor),0);
    if(sd.SystemAcl!=null){byte[] bytes=new byte[sd.SystemAcl.BinaryLength];sd.SystemAcl.GetBinaryForm(bytes,0);buffer=Marshal.AllocHGlobal(bytes.Length);Marshal.Copy(bytes,0,buffer,bytes.Length);}
    uint result=SetSecurityInfo(handle,registry?4U:1U,0x40000008,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,buffer);
    if(result!=0)throw new Win32Exception((int)result);
   } finally {if(buffer!=IntPtr.Zero)Marshal.FreeHGlobal(buffer);if(handle!=IntPtr.Zero){if(registry)RegCloseKey(handle);else CloseHandle(handle);}}
  }
 }
}
