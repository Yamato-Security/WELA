// Read-only WEC runtime observations. No subscription create/save/retry API.
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
namespace Wela.WecRuntime {
 public sealed class Value {
  public string State="Unknown"; public uint? NativeType; public uint Count;
  public int ErrorCode; public string Diagnostic=""; public object Data;
 }
 public static class Native {
  [DllImport("wecapi.dll",CharSet=CharSet.Unicode,SetLastError=true)]
  [return:MarshalAs(UnmanagedType.Bool)]
  static extern bool EcGetSubscriptionRunTimeStatus(string subscription,int property,string source,uint flags,uint size,IntPtr buffer,out uint used);
  const uint MaximumBytes=1048576;
  static void Range(IntPtr buffer,uint size,IntPtr pointer,long length) {
   long offset=pointer.ToInt64()-buffer.ToInt64();
   if(pointer==IntPtr.Zero||offset<16||length<0||offset>size||length>size-offset)throw new InvalidOperationException("Native variant points outside its returned buffer.");
  }
  static string Text(IntPtr buffer,uint size,IntPtr pointer) {
   Range(buffer,size,pointer,2);long offset=pointer.ToInt64()-buffer.ToInt64();
   StringBuilder value=new StringBuilder();
   for(int i=0;i<32768&&offset+2L*i+2<=size;i++) {
    char c=(char)(ushort)Marshal.ReadInt16(pointer,i*2);if(c==0)return value.ToString();value.Append(c);
   }
   throw new InvalidOperationException("Native string is unterminated or exceeds the character limit.");
  }
  // Public only to permit safe allocated-buffer ABI/type regression tests.
  public static Value Decode(IntPtr buffer,uint size,int property) {
   if(buffer==IntPtr.Zero||size<16||size>MaximumBytes||property<0||property>6)throw new InvalidOperationException("Invalid runtime buffer or property.");
   uint count=unchecked((uint)Marshal.ReadInt32(buffer,8));uint type=unchecked((uint)Marshal.ReadInt32(buffer,12));
   Value value=new Value {NativeType=type,Count=count};
   if(type==0) {if(count!=0)throw new InvalidOperationException("Null runtime variant has a nonzero count.");value.State="NotAvailable";return value;}
   uint expected=property==0||property==1?2U:property==2?4U:property==5?132U:3U;
   if(type!=expected)throw new InvalidOperationException("Unexpected EC_VARIANT type for runtime property.");
   if(type==2) {value.Data=unchecked((uint)Marshal.ReadInt32(buffer));}
   else if(type==3) {value.Data=unchecked((ulong)Marshal.ReadInt64(buffer));}
   else if(type==4) {value.Data=Text(buffer,size,Marshal.ReadIntPtr(buffer));}
   else {
    if(count>4096)throw new InvalidOperationException("Native source inventory exceeds 4096 entries.");
    string[] values=new string[count];IntPtr pointers=Marshal.ReadIntPtr(buffer);
    if(count!=0)Range(buffer,size,pointers,(long)count*IntPtr.Size);
    for(int i=0;i<count;i++)values[i]=Text(buffer,size,Marshal.ReadIntPtr(pointers,i*IntPtr.Size));
    value.Data=values;
   }
   value.State="Observed";return value;
  }
  public static Value Read(string subscription,string source,int property) {
   if(String.IsNullOrWhiteSpace(subscription)||subscription.Length>128||subscription.IndexOf('\0')>=0||property<0||property>6||source!=null&&(source.Length>32768||source.IndexOf('\0')>=0))throw new ArgumentException("Invalid selected subscription/source/property.");
   uint size=16;
   for(int attempt=0;attempt<3;attempt++) {
    IntPtr buffer=Marshal.AllocHGlobal((int)size);
    try {
     uint used;bool success=EcGetSubscriptionRunTimeStatus(subscription,property,source,0,size,buffer,out used);
     int error=Marshal.GetLastWin32Error();
     if(success) {
      if(used<16||used>size)return new Value {ErrorCode=13,Diagnostic="Native runtime returned an invalid used-buffer length."};
      try{return Decode(buffer,used,property);}catch(Exception e){return new Value {ErrorCode=13,Diagnostic=e.Message};}
     }
     if(error!=122)return new Value {ErrorCode=error,Diagnostic=new Win32Exception(error).Message};
     if(used<=size||used>MaximumBytes)return new Value {ErrorCode=122,Diagnostic="Runtime buffer growth is invalid or exceeds one MiB."};
     size=used;
    }finally {Marshal.FreeHGlobal(buffer);}
   }
   return new Value {ErrorCode=122,Diagnostic="Runtime buffer changed repeatedly; observation is incomplete."};
  }
 }
}
