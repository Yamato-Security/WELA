// Existing-only native WEC authorization setter. No creation, deletion, activation or other setters.
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
namespace Wela.WecAuthorization {
 public sealed class Edit : IDisposable {
  public const string SourceSha256="__WELA_SOURCE_SHA256__";
  [StructLayout(LayoutKind.Explicit, Size=16)] struct Variant {
   [FieldOffset(0)] public IntPtr Text; [FieldOffset(8)] public uint Count; [FieldOffset(12)] public uint Type;
  }
  [DllImport("wecapi.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr EcOpenSubscription(string name,uint access,uint flags);
  [DllImport("wecapi.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool EcGetSubscriptionProperty(IntPtr handle,int property,uint flags,uint size,IntPtr value,out uint used);
  [DllImport("wecapi.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool EcSetSubscriptionProperty(IntPtr handle,int property,uint flags,ref Variant value);
  [DllImport("wecapi.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool EcSaveSubscription(IntPtr handle,uint flags);
  [DllImport("wecapi.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool EcClose(IntPtr handle);
  IntPtr handle; readonly string name,oldQuery,oldDescription,oldAuthorization;
  public string OriginalQuery {get{return oldQuery;}}
  public string OriginalDescription {get{return oldDescription;}}
  public string OriginalAuthorization {get{return oldAuthorization;}}
  public bool SaveAttempted {get;private set;}
  public static void ValidateAuthorization(string value) {
   if(String.IsNullOrEmpty(value)||value.Length>4096||!value.StartsWith("O:NSG:NSD:",StringComparison.Ordinal))throw new ArgumentException("Explicit canonical domain-source authorization required.");
   var matches=System.Text.RegularExpressions.Regex.Matches(value,@"\(A;;GA;;;(S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+)\)");
   if(matches.Count<1||matches.Count>32)throw new ArgumentException("Select 1 to 32 source SIDs.");
   var expected=new StringBuilder("O:NSG:NSD:");string prior=null;
   foreach(System.Text.RegularExpressions.Match match in matches) {
    string sid=match.Groups[1].Value;string[] parts=sid.Split('-');
    for(int i=4;i<parts.Length;i++){uint number;if(!UInt32.TryParse(parts[i],System.Globalization.NumberStyles.None,System.Globalization.CultureInfo.InvariantCulture,out number)||number.ToString(System.Globalization.CultureInfo.InvariantCulture)!=parts[i])throw new ArgumentException("Noncanonical SID subauthority.");}
    if(prior!=null&&StringComparer.Ordinal.Compare(prior,sid)>=0)throw new ArgumentException("SIDs must be unique and sorted.");prior=sid;expected.Append(match.Value);
   }
   if(!String.Equals(expected.ToString(),value,StringComparison.Ordinal))throw new ArgumentException("Unsupported authorization descriptor.");
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
     if(property==27){if(type!=8)throw new InvalidOperationException("Subscription type is not UInt32.");return unchecked((uint)Marshal.ReadInt32(buffer));}
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
   if((bool)Read(h,0)||(uint)Read(h,27)!=0||!String.Equals((string)Read(h,7),"http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog",StringComparison.Ordinal)||!String.Equals((string)Read(h,11),"HTTP",StringComparison.Ordinal)||!String.Equals((string)Read(h,19),"ForwardedEvents",StringComparison.Ordinal)||!String.Equals((string)Read(h,10),oldQuery,StringComparison.Ordinal)||!String.Equals((string)Read(h,6),oldDescription,StringComparison.Ordinal)||!String.Equals((string)Read(h,31),oldAuthorization,StringComparison.Ordinal))throw new InvalidOperationException("Native enabled/query/description/authorization changed since review.");
  }
  public Edit(string id) {
   if(String.IsNullOrWhiteSpace(id)||id.Length>128||id.IndexOf('\0')>=0)throw new ArgumentException("Invalid subscription ID.");
   name=id;handle=EcOpenSubscription(name,3,2);if(handle==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());
   try{oldQuery=(string)Read(handle,10);oldDescription=(string)Read(handle,6);oldAuthorization=(string)Read(handle,31);ValidateAuthorization(oldAuthorization);Check(handle);}catch{Dispose();throw;}
  }
  public void Save(string authorization) {
   if(handle==IntPtr.Zero)throw new ObjectDisposedException("Edit");
   if(SaveAttempted)throw new InvalidOperationException("A native edit may be saved only once.");
   ValidateAuthorization(authorization);
   if(String.Equals(authorization,oldAuthorization,StringComparison.Ordinal))throw new InvalidOperationException("Idempotent authorization must not save.");
   IntPtr fresh=EcOpenSubscription(name,1,2);if(fresh==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());
   try{Check(fresh);}finally{EcClose(fresh);}
   IntPtr text=Marshal.StringToHGlobalUni(authorization);
   try {
    Variant value=new Variant{Text=text,Count=0,Type=4};
    if(!EcSetSubscriptionProperty(handle,31,0,ref value))throw new Win32Exception(Marshal.GetLastWin32Error());
    SaveAttempted=true;
    if(!EcSaveSubscription(handle,0))throw new Win32Exception(Marshal.GetLastWin32Error());
   }finally{Marshal.FreeHGlobal(text);}
  }
  public void Dispose(){if(handle!=IntPtr.Zero){EcClose(handle);handle=IntPtr.Zero;}}
 }
}
