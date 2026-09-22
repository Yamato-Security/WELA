// Read-only WEC names, returned only after complete bounded native enumeration.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
namespace Wela.WecInventory {
 public static class Reader {
  public const string SourceSha256="__WELA_SOURCE_SHA256__";
  const uint Capacity=1024;
  [DllImport("wecapi.dll",SetLastError=true)] static extern IntPtr EcOpenSubscriptionEnum(uint flags);
  [DllImport("wecapi.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool EcEnumNextSubscription(IntPtr enumeration,uint size,IntPtr name,out uint used);
  [DllImport("wecapi.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool EcClose(IntPtr handle);
  // Public only for safe allocated-buffer ABI and boundary regression tests.
  public static string DecodeName(IntPtr buffer,uint used,uint capacity) {
   if(buffer==IntPtr.Zero||capacity<2||capacity>Capacity||used<2||used>capacity)throw new InvalidDataException("Invalid native subscription-name buffer.");
   if(Marshal.ReadInt16(buffer,checked((int)(used-1)*2))!=0)throw new InvalidDataException("Native subscription name is not terminated.");
   byte[] bytes=new byte[checked((int)(used-1)*2)];Marshal.Copy(buffer,bytes,0,bytes.Length);
   string name=new UnicodeEncoding(false,false,true).GetString(bytes);
   if(name.IndexOf('\0')>=0)throw new InvalidDataException("Native subscription name contains an embedded terminator.");
   return name;
  }
  // Public so duplicate, count and aggregate bounds can be tested without Windows.
  public static string[] ValidateNames(string[] names) {
   if(names==null||names.Length>4096)throw new InvalidDataException("Native subscription inventory exceeds 4096 entries.");
   var unique=new HashSet<string>(StringComparer.OrdinalIgnoreCase);long characters=0;
   foreach(string name in names) {
    if(String.IsNullOrEmpty(name)||name.Length>=Capacity||name.IndexOf('\0')>=0||!unique.Add(name))throw new InvalidDataException("Native subscription inventory contains an invalid or duplicate name.");
    new UnicodeEncoding(false,false,true).GetBytes(name);
    characters+=name.Length+1;if(characters>1048576)throw new InvalidDataException("Native subscription inventory exceeds its total character bound.");
   }
   string[] result=(string[])names.Clone();Array.Sort(result,StringComparer.Ordinal);return result;
  }
  public static string[] ReadNames() {
   IntPtr handle=EcOpenSubscriptionEnum(0);if(handle==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());
   try {
    IntPtr buffer=Marshal.AllocHGlobal(checked((int)Capacity*2));
    try {
     var names=new List<string>();long characters=0;
     while(true) {
      uint used;
      if(!EcEnumNextSubscription(handle,Capacity,buffer,out used)) {int error=Marshal.GetLastWin32Error();if(error==259)return ValidateNames(names.ToArray());throw new Win32Exception(error);}
      string name=DecodeName(buffer,used,Capacity);characters+=name.Length+1;
      if(names.Count>=4096||characters>1048576)throw new InvalidDataException("Native subscription inventory exceeded its bounds; no absence is established.");
      names.Add(name);
     }
    }finally {Marshal.FreeHGlobal(buffer);}
   }finally {EcClose(handle);}
  }
 }
}
