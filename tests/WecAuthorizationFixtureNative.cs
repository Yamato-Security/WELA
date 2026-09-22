// Read-only disposable-fixture inventory; bypasses console/native text decoding.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
namespace Wela.WecAuthorizationFixture {
 public static class Inventory {
  [DllImport("wecapi.dll",SetLastError=true)] static extern IntPtr EcOpenSubscriptionEnum(uint flags);
  [DllImport("wecapi.dll",CharSet=CharSet.Unicode,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool EcEnumNextSubscription(IntPtr enumeration,uint size,StringBuilder name,out uint used);
  [DllImport("wecapi.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool EcClose(IntPtr handle);
  public static string[] Read() {
   IntPtr handle=EcOpenSubscriptionEnum(0);if(handle==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());
   try {
    var names=new List<string>();
    while(true) {
     var name=new StringBuilder(4096);uint used;
     if(!EcEnumNextSubscription(handle,4096,name,out used)) {int error=Marshal.GetLastWin32Error();if(error==259)return names.ToArray();throw new Win32Exception(error);}
     if(used<2||used>4096||name.Length==0||name.Length+1!=used||names.Count>=64||names.Contains(name.ToString()))throw new InvalidOperationException("Disposable native subscription inventory is invalid, duplicated or exceeds its bound.");
     names.Add(name.ToString());
    }
   }finally {EcClose(handle);}
  }
 }
}
