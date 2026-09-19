// Narrow existing-only WEC setter. No create/delete, enable or source-property setter.
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
namespace Wela.WecUpdate {
 public sealed class Edit : IDisposable {
  [StructLayout(LayoutKind.Explicit,Size=16)] struct Variant {
   [FieldOffset(0)] public IntPtr Text; [FieldOffset(8)] public uint Count; [FieldOffset(12)] public uint Type;
  }
  [DllImport("wecapi.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr EcOpenSubscription(string name,uint access,uint flags);
  [DllImport("wecapi.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool EcGetSubscriptionProperty(IntPtr handle,int property,uint flags,uint size,IntPtr value,out uint used);
  [DllImport("wecapi.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool EcSetSubscriptionProperty(IntPtr handle,int property,uint flags,ref Variant value);
  [DllImport("wecapi.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool EcSaveSubscription(IntPtr handle,uint flags);
  [DllImport("wecapi.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool EcClose(IntPtr handle);
  IntPtr handle; readonly string name,oldQuery,oldDescription;
  static object Read(IntPtr h,int property) {
   uint size=16;
   for(int attempt=0;attempt<3;attempt++) {
    IntPtr buffer=Marshal.AllocHGlobal((int)size);
    try {
     uint used;bool ok=EcGetSubscriptionProperty(h,property,0,size,buffer,out used);int error=Marshal.GetLastWin32Error();
     if(!ok) {if(error!=122)throw new Win32Exception(error);if(used<=size||used>1048576)throw new InvalidOperationException("Invalid native property buffer size.");size=used;continue;}
     if(used<16||used>size)throw new InvalidOperationException("Invalid native property length.");
     int type=Marshal.ReadInt32(buffer,12);
     if(property==0) {if(type!=1)throw new InvalidOperationException("Enabled property is not Boolean.");int value=Marshal.ReadInt32(buffer);if(value!=0&&value!=1)throw new InvalidOperationException("Invalid native Boolean.");return value==1;}
     if(type==0&&property==6)return "";
     if(type!=4)throw new InvalidOperationException("Expected scalar native string.");
     IntPtr pointer=Marshal.ReadIntPtr(buffer);long offset=pointer.ToInt64()-buffer.ToInt64();
     if(pointer==IntPtr.Zero||offset<16||offset>used-2)throw new InvalidOperationException("Native string pointer is outside its buffer.");
     StringBuilder text=new StringBuilder();
     for(int i=0;i<524288&&offset+2L*i+2<=used;i++){char c=(char)(ushort)Marshal.ReadInt16(pointer,2*i);if(c==0)return text.ToString();text.Append(c);}
     throw new InvalidOperationException("Unterminated native string.");
    } finally {Marshal.FreeHGlobal(buffer);}
   }
   throw new InvalidOperationException("Native property changed repeatedly.");
  }
  void Check(IntPtr h) {
   if((bool)Read(h,0))throw new InvalidOperationException("Subscription must remain disabled.");
   if(!String.Equals((string)Read(h,10),oldQuery,StringComparison.Ordinal)||!String.Equals((string)Read(h,6),oldDescription,StringComparison.Ordinal))throw new InvalidOperationException("Native query/description changed since review.");
  }
  public Edit(string id,string expectedQuery,string expectedDescription) {
   if(String.IsNullOrWhiteSpace(id)||id.Length>128||id.IndexOf('\0')>=0)throw new ArgumentException("Invalid subscription ID.");
   name=id;oldQuery=expectedQuery;oldDescription=expectedDescription;
   handle=EcOpenSubscription(name,3,2);if(handle==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());
   try{Check(handle);}catch{Dispose();throw;}
  }
  void Set(int property,string text) {
   if(text==null||text.Length>262144||text.IndexOf('\0')>=0)throw new ArgumentException("Invalid bounded string property.");
   IntPtr value=Marshal.StringToHGlobalUni(text);
   try{Variant v=new Variant {Text=value,Type=4,Count=0};if(!EcSetSubscriptionProperty(handle,property,0,ref v))throw new Win32Exception(Marshal.GetLastWin32Error());}finally{Marshal.FreeHGlobal(value);}
  }
  public void Save(string query,string description) {
   if(handle==IntPtr.Zero)throw new ObjectDisposedException("Edit");
   // A separately opened view detects changes since the staged handle was opened.
   IntPtr fresh=EcOpenSubscription(name,1,2);if(fresh==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());
   try{Check(fresh);}finally{EcClose(fresh);}
   Set(10,query);Set(6,description);
   if(!EcSaveSubscription(handle,0))throw new Win32Exception(Marshal.GetLastWin32Error());
  }
  public void Dispose(){if(handle!=IntPtr.Zero){EcClose(handle);handle=IntPtr.Zero;}}
 }
}
