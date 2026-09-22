// Existing-only native WEC Enabled setter. No create/delete or other setters.
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
namespace Wela.WecState {
 public sealed class Edit : IDisposable {
  [StructLayout(LayoutKind.Explicit, Size=16)] struct Variant {
   [FieldOffset(0)] public int Boolean; [FieldOffset(8)] public uint Count; [FieldOffset(12)] public uint Type;
  }
  [DllImport("wecapi.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr EcOpenSubscription(string name,uint access,uint flags);
  [DllImport("wecapi.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool EcGetSubscriptionProperty(IntPtr handle,int property,uint flags,uint size,IntPtr value,out uint used);
  [DllImport("wecapi.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool EcSetSubscriptionProperty(IntPtr handle,int property,uint flags,ref Variant value);
  [DllImport("wecapi.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool EcSaveSubscription(IntPtr handle,uint flags);
  [DllImport("wecapi.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool EcClose(IntPtr handle);
  [DllImport("advapi32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool GetTokenInformation(IntPtr token,int information,IntPtr buffer,int size,out int used);
  IntPtr handle; readonly string name,oldQuery,oldDescription,oldAuthorization; readonly bool oldEnabled;
  public bool OriginalEnabled {get{return oldEnabled;}}
  public string OriginalQuery {get{return oldQuery;}}
  public string OriginalDescription {get{return oldDescription;}}
  public string OriginalAuthorization {get{return oldAuthorization;}}
  public bool SaveAttempted {get;private set;}
  // TOKEN_STATISTICS: TokenId, AuthenticationId and ModifiedId, plus token type.
  public static string TokenKey(IntPtr token) {
   IntPtr buffer=Marshal.AllocHGlobal(56);
   try {int used;if(!GetTokenInformation(token,10,buffer,56,out used))throw new Win32Exception(Marshal.GetLastWin32Error());if(used!=56)throw new InvalidOperationException("Unexpected TOKEN_STATISTICS size.");
    byte[] bytes=new byte[56];Marshal.Copy(buffer,bytes,0,bytes.Length);return BitConverter.ToString(bytes).Replace("-","");
   }finally{Marshal.FreeHGlobal(buffer);}
  }
  static object Read(IntPtr h,int property) {
   uint size=16;
   for(int attempt=0;attempt<3;attempt++) {
    IntPtr buffer=Marshal.AllocHGlobal((int)size);
    try {
     uint used;bool ok=EcGetSubscriptionProperty(h,property,0,size,buffer,out used);int error=Marshal.GetLastWin32Error();
     if(!ok){if(error!=122)throw new Win32Exception(error);if(used<=size||used>1048576)throw new InvalidOperationException("Invalid native property buffer size.");size=used;continue;}
     if(used<16||used>size)throw new InvalidOperationException("Invalid native property length.");
     int type=Marshal.ReadInt32(buffer,12);
     if(property==0){if(type!=1)throw new InvalidOperationException("Enabled is not a scalar Boolean.");int value=Marshal.ReadInt32(buffer);if(value!=0&&value!=1)throw new InvalidOperationException("Invalid native Boolean.");return value==1;}
     if(type==0&&property==6)return "";
     if(type!=4)throw new InvalidOperationException("Expected scalar native string.");
     IntPtr pointer=Marshal.ReadIntPtr(buffer);long offset=pointer.ToInt64()-buffer.ToInt64();
     if(pointer==IntPtr.Zero||offset<16||offset>used-2)throw new InvalidOperationException("Native string pointer is outside its buffer.");
     StringBuilder text=new StringBuilder();
     for(int i=0;i<524288&&offset+2L*i+2<=used;i++){char c=(char)(ushort)Marshal.ReadInt16(pointer,2*i);if(c==0)return text.ToString();text.Append(c);}
     throw new InvalidOperationException("Unterminated native string.");
    }finally{Marshal.FreeHGlobal(buffer);}
   }
   throw new InvalidOperationException("Native property changed repeatedly.");
  }
  void Check(IntPtr h) {
   if((bool)Read(h,0)!=oldEnabled||!String.Equals((string)Read(h,10),oldQuery,StringComparison.Ordinal)||!String.Equals((string)Read(h,6),oldDescription,StringComparison.Ordinal)||!String.Equals((string)Read(h,31),oldAuthorization,StringComparison.Ordinal))throw new InvalidOperationException("Native enabled/query/description/authorization changed since review.");
  }
  public Edit(string id) {
   if(String.IsNullOrWhiteSpace(id)||id.Length>128||id.IndexOf('\0')>=0)throw new ArgumentException("Invalid subscription ID.");
   name=id;handle=EcOpenSubscription(name,3,2);if(handle==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());
   try{oldEnabled=(bool)Read(handle,0);oldQuery=(string)Read(handle,10);oldDescription=(string)Read(handle,6);oldAuthorization=(string)Read(handle,31);}catch{Dispose();throw;}
  }
  public void Save(bool enabled) {
   if(handle==IntPtr.Zero)throw new ObjectDisposedException("Edit");
   if(SaveAttempted)throw new InvalidOperationException("A native edit may be saved only once.");
   if(enabled==oldEnabled)throw new InvalidOperationException("Idempotent state must not save or reactivate a subscription.");
   IntPtr fresh=EcOpenSubscription(name,1,2);if(fresh==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());
   try{Check(fresh);}finally{EcClose(fresh);}
   Variant value=new Variant{Boolean=enabled?1:0,Count=0,Type=1};
   if(!EcSetSubscriptionProperty(handle,0,0,ref value))throw new Win32Exception(Marshal.GetLastWin32Error());
   SaveAttempted=true;
   if(!EcSaveSubscription(handle,0))throw new Win32Exception(Marshal.GetLastWin32Error());
  }
  public void Dispose(){if(handle!=IntPtr.Zero){EcClose(handle);handle=IntPtr.Zero;}}
 }
}
