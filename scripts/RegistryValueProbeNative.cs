// Fixed existing current-user WELA probe key: one owned temporary value lifecycle.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
namespace Wela.RegistryValueProbe {
 public sealed class Ace { public string Binary; public int Type,Flags,Mask; public string Sid; public bool Ordinary; }
 public sealed class Value {public string Name,DataBase64; public uint Type;}
 public sealed class Operation {public bool Succeeded,CleanupComplete;public string Nonce,Name,BeforeValue,AfterValue,HandleId,StartedUtc,WriteReturnedUtc,CompletedUtc,Diagnostic;public Snapshot Before,After;}
 public sealed class Snapshot {
  public string Path,Kind,Identity; public bool IsDirectory;
  public string DescriptorBase64,Owner,Group,DaclBase64; public int ControlFlags,SecurityInformation;
  public string DescriptorScope; public Ace[] Aces; public Value[] Values;
 }
 public static class Descriptor {
  public const string SourceSha256="__WELA_REGISTRY_VALUE_PROBE_SOURCE_SHA256__";
  public static string Bytes(GenericAcl value) { if(value==null)return null;byte[] b=new byte[value.BinaryLength];value.GetBinaryForm(b,0);return Convert.ToBase64String(b); }
  public static string Bytes(GenericAce value) { byte[] b=new byte[value.BinaryLength];value.GetBinaryForm(b,0);return Convert.ToBase64String(b); }
  static string Sid(SecurityIdentifier value) {return value==null?null:value.Value;}
  public static RawSecurityDescriptor Parse(string value) {
   byte[] b=Convert.FromBase64String(value);
   if(b.Length<20||b.Length>1048576||Convert.ToBase64String(b)!=value)throw new InvalidOperationException("Invalid or noncanonical descriptor bytes.");
   RawSecurityDescriptor sd=new RawSecurityDescriptor(b,0);
   return sd;
  }
  public static void AssertProbeCapacity(Value[] values) {
   if(values==null||values.Length>=128)throw new InvalidOperationException("Registry inventory has no capacity for an owned probe value.");
   long total=0;foreach(Value value in values){if(value==null||value.DataBase64==null)throw new InvalidOperationException("Incomplete typed value inventory.");int size=Convert.FromBase64String(value.DataBase64).Length;if(size>65536)throw new InvalidOperationException("Value exceeds inventory bound.");total+=size;}
   int reserved=Encoding.Unicode.GetByteCount("WELA_BEFORE_"+new string('0',32)+"\0");
   if(total+reserved>1048576)throw new InvalidOperationException("Registry byte inventory has no capacity for an owned probe value.");
  }
  public static Snapshot Observe(string path,string identity,byte[] bytes) {
   string encoded=Convert.ToBase64String(bytes);RawSecurityDescriptor sd=Parse(encoded);List<Ace> entries=new List<Ace>();
   if(sd.SystemAcl!=null)foreach(GenericAce ace in sd.SystemAcl){CommonAce common=ace as CommonAce;bool ordinary=common!=null&&!common.IsCallback&&common.AceType==AceType.SystemAudit;entries.Add(new Ace {Binary=Bytes(ace),Type=(int)ace.AceType,Flags=(int)ace.AceFlags,Mask=ordinary?common.AccessMask:0,Sid=ordinary?common.SecurityIdentifier.Value:null,Ordinary=ordinary});}
   return new Snapshot {Path=path,Kind="Registry",Identity=identity,IsDirectory=false,DescriptorBase64=encoded,Owner=Sid(sd.Owner),Group=Sid(sd.Group),DaclBase64=Bytes(sd.DiscretionaryAcl),ControlFlags=(int)sd.ControlFlags,SecurityInformation=511,DescriptorScope="WinSDK-defined sections 0x1ff; future sections unobserved",Aces=entries.ToArray()};
  }
 }
 sealed class Privilege : IDisposable {
  [StructLayout(LayoutKind.Sequential)] struct Luid {public uint Low;public int High;}
  [StructLayout(LayoutKind.Sequential)] struct TokenPrivileges {public uint Count;public Luid Luid;public uint Attributes;}
  [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
  [DllImport("kernel32.dll")] static extern IntPtr GetCurrentThread();
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr value);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenThreadToken(IntPtr thread,uint access,bool self,out IntPtr token);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool LookupPrivilegeValue(string system,string name,out Luid luid);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool AdjustTokenPrivileges(IntPtr token,bool disable,ref TokenPrivileges value,uint size,out TokenPrivileges previous,out uint required);
  IntPtr token;TokenPrivileges previous;
  public Privilege(){IntPtr thread;
   if(OpenThreadToken(GetCurrentThread(),8,true,out thread)){CloseHandle(thread);throw new InvalidOperationException("Impersonated recovery is unsupported.");}
   int error=Marshal.GetLastWin32Error();if(error!=1008)throw new Win32Exception(error);
   if(!OpenProcessToken(GetCurrentProcess(),0x28,out token))throw new Win32Exception(Marshal.GetLastWin32Error());
   try{Luid luid;if(!LookupPrivilegeValue(null,"SeSecurityPrivilege",out luid))throw new Win32Exception(Marshal.GetLastWin32Error());TokenPrivileges request=new TokenPrivileges {Count=1,Luid=luid,Attributes=2};uint required;bool ok=AdjustTokenPrivileges(token,false,ref request,(uint)Marshal.SizeOf(typeof(TokenPrivileges)),out previous,out required);error=Marshal.GetLastWin32Error();if(!ok||error!=0)throw new Win32Exception(error,"SeSecurityPrivilege is unavailable.");}
   catch{CloseHandle(token);token=IntPtr.Zero;throw;}
  }
  public void Dispose(){if(token==IntPtr.Zero)return;try{TokenPrivileges ignored;uint required;bool ok=AdjustTokenPrivileges(token,false,ref previous,(uint)Marshal.SizeOf(typeof(TokenPrivileges)),out ignored,out required);int error=Marshal.GetLastWin32Error();if(!ok||error!=0)throw new Win32Exception(error,"SeSecurityPrivilege restoration failed.");}finally{CloseHandle(token);token=IntPtr.Zero;}}
 }
 public sealed class Target : IDisposable {
  [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr value);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] static extern int RegOpenKeyExW(IntPtr root,string name,uint options,uint access,out IntPtr key);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] static extern int RegQueryValueExW(IntPtr key,string name,IntPtr reserved,out uint type,IntPtr data,ref uint size);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] static extern int RegQueryInfoKeyW(IntPtr key,IntPtr cls,IntPtr clsSize,IntPtr reserved,IntPtr subKeys,IntPtr maxSubKey,IntPtr maxClass,IntPtr values,IntPtr maxValueName,IntPtr maxValue,IntPtr securitySize,out long written);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] static extern int RegEnumKeyExW(IntPtr key,uint index,StringBuilder name,ref uint length,IntPtr reserved,IntPtr cls,IntPtr clsLength,IntPtr written);
  [DllImport("advapi32.dll")] static extern int RegCloseKey(IntPtr key);
  [DllImport("ntdll.dll")] static extern int NtQueryKey(IntPtr key,int cls,IntPtr information,uint length,out uint resultLength);
  [DllImport("advapi32.dll")] static extern uint GetSecurityInfo(IntPtr handle,uint kind,uint flags,out IntPtr owner,out IntPtr group,out IntPtr dacl,out IntPtr sacl,out IntPtr descriptor);
  [DllImport("advapi32.dll")] static extern uint GetSecurityDescriptorLength(IntPtr descriptor);

  readonly string path,nativePath;readonly List<IntPtr> keys=new List<IntPtr>();IntPtr handle;Privilege privilege;
  readonly bool writable;
  public Target(bool write){
   writable=write;
   string sid=TokenReader.Snapshot().Sid;
   string path="HKEY_USERS\\"+sid+"\\Software\\WELA\\AuditProbe";
   this.path=path;
   if(String.IsNullOrEmpty(path)||path.IndexOfAny(new char[]{'/','*','?','%','\0'})>=0)throw new InvalidOperationException("Exact local registry path required.");
   string[] parts=path.Split('\\');IntPtr root;
   if(parts[0]=="HKEY_LOCAL_MACHINE"){root=new IntPtr(unchecked((int)0x80000002));nativePath="\\REGISTRY\\MACHINE";}
   else if(parts[0]=="HKEY_USERS"){root=new IntPtr(unchecked((int)0x80000003));nativePath="\\REGISTRY\\USER";}
   else throw new InvalidOperationException("Only selected HKLM/HKU keys are supported.");
   if(parts.Length<2)throw new InvalidOperationException("Hive roots cannot be recovered.");
   for(int i=1;i<parts.Length;i++){if(parts[i].Length==0||parts[i]=="."||parts[i]=="..")throw new InvalidOperationException("Ambiguous registry path.");nativePath+="\\"+parts[i];}
   try{
    privilege=new Privilege();IntPtr current=root;
    for(int i=1;i<parts.Length;i++){
     IntPtr opened;int error=RegOpenKeyExW(current,parts[i],8,0x01020101U|(i==parts.Length-1?(8U|(write?2U:0U)):0U),out opened);
     if(error!=0)throw new Win32Exception(error,"Selected registry component open failed.");keys.Add(opened);current=opened;
     uint type,size=0;error=RegQueryValueExW(current,"SymbolicLinkValue",IntPtr.Zero,out type,IntPtr.Zero,ref size);
     if(error==0&&type==6)throw new InvalidOperationException("Registry symbolic-link component refused.");if(error!=0&&error!=2)throw new Win32Exception(error,"Registry link state is unreadable.");
    }
    handle=current;Check();AssertEmpty();
   }catch{Dispose();throw;}
  }
  string Check(){
   if(handle==IntPtr.Zero)throw new ObjectDisposedException("Target");uint required;int status=NtQueryKey(handle,3,IntPtr.Zero,0,out required);
   if((status!=unchecked((int)0xC0000023)&&status!=unchecked((int)0x80000005))||required<6||required>65536)throw new InvalidOperationException("Native registry name query is unavailable.");
   IntPtr buffer=Marshal.AllocHGlobal((int)required);
   try{uint actual;status=NtQueryKey(handle,3,buffer,required,out actual);if(status!=0||actual>required)throw new InvalidOperationException("Native registry name query failed.");int size=Marshal.ReadInt32(buffer);if(size<2||size%2!=0||size>required-4)throw new InvalidOperationException("Native registry name is malformed.");string name=Marshal.PtrToStringUni(IntPtr.Add(buffer,4),size/2);if(!String.Equals(name,nativePath,StringComparison.OrdinalIgnoreCase))throw new InvalidOperationException("Held registry name differs from the selected path.");}finally{Marshal.FreeHGlobal(buffer);}
   long written;int error=RegQueryInfoKeyW(handle,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,out written);if(error!=0)throw new Win32Exception(error,"Registry last-write observation failed.");return path+":"+written;
  }
  public void AssertEmpty(){if(handle==IntPtr.Zero)throw new ObjectDisposedException("Target");StringBuilder name=new StringBuilder(256);uint size=256;int error=RegEnumKeyExW(handle,0,name,ref size,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero);if(error==0||error==234)throw new InvalidOperationException("Recovery requires an observed empty registry descendant inventory.");if(error!=259)throw new Win32Exception(error,"Registry child enumeration is unknown.");}
  public Snapshot Read(){
   string identity=Check();AssertEmpty();IntPtr owner,group,dacl,sacl,descriptor;uint error=GetSecurityInfo(handle,4,511,out owner,out group,out dacl,out sacl,out descriptor);if(error!=0)throw new Win32Exception((int)error,"Full SDK-defined registry descriptor read failed.");byte[] bytes;
   try{uint size=GetSecurityDescriptorLength(descriptor);if(size<20||size>1048576)throw new InvalidOperationException("Invalid native descriptor size.");bytes=new byte[size];Marshal.Copy(descriptor,bytes,0,(int)size);}finally{LocalFree(descriptor);}
   AssertEmpty();if(Check()!=identity)throw new InvalidOperationException("Registry last-write identity changed during observation.");Snapshot result=Descriptor.Observe(path,identity,bytes);result.Values=ReadValues();if(Check()!=identity)throw new InvalidOperationException("Registry changed during value observation.");return result;
  }
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] static extern int RegEnumValueW(IntPtr key,uint index,StringBuilder name,ref uint nameLength,IntPtr reserved,out uint type,byte[] data,ref uint size);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] static extern int RegSetValueExW(IntPtr key,string name,uint reserved,uint type,byte[] data,uint size);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] static extern int RegDeleteValueW(IntPtr key,string name);
  [DllImport("kernel32.dll",ExactSpelling=true)] static extern void GetSystemTimePreciseAsFileTime(out long value);
  public static DateTime UtcNow(){long n;GetSystemTimePreciseAsFileTime(out n);return DateTime.FromFileTimeUtc(n);}
  Value[] ReadValues(){
   List<Value> values=new List<Value>();long total=0;
   for(uint i=0;i<=128;i++){
    StringBuilder name=new StringBuilder(16384);uint length=16384,type,size=65536;byte[] data=new byte[size];
    int error=RegEnumValueW(handle,i,name,ref length,IntPtr.Zero,out type,data,ref size);
    if(error==259)break;if(error!=0)throw new Win32Exception(error,"Bounded registry value inventory failed.");
    if(i==128||size>65536||length>=16384||total+size>1048576)throw new InvalidOperationException("Registry value inventory exceeds bound.");
    total+=size;byte[] exact=new byte[size];Array.Copy(data,exact,size);values.Add(new Value{Name=name.ToString(),Type=type,DataBase64=Convert.ToBase64String(exact)});
   }
   values.Sort((a,b)=>String.CompareOrdinal(a.Name,b.Name));return values.ToArray();
  }
  static bool SameValues(Value[] a,Value[] b){if(a.Length!=b.Length)return false;for(int i=0;i<a.Length;i++)if(a[i].Name!=b[i].Name||a[i].Type!=b[i].Type||a[i].DataBase64!=b[i].DataBase64)return false;return true;}
  Value Find(string name){
   uint type,size=0;int error=RegQueryValueExW(handle,name,IntPtr.Zero,out type,IntPtr.Zero,ref size);
   if(error==2)return null;if(error!=0)throw new Win32Exception(error,"Owned value size query failed.");
   if(size>65536)throw new InvalidOperationException("Owned value exceeds bound; refusing modification.");
   IntPtr data=Marshal.AllocHGlobal((int)Math.Max(size,1));
   try{uint actual=size,currentType;error=RegQueryValueExW(handle,name,IntPtr.Zero,out currentType,data,ref actual);if(error!=0||actual!=size||currentType!=type)throw new InvalidOperationException("Owned value changed during exact query.");byte[] bytes=new byte[actual];if(actual>0)Marshal.Copy(data,bytes,0,(int)actual);return new Value{Name=name,Type=type,DataBase64=Convert.ToBase64String(bytes)};}
   finally{Marshal.FreeHGlobal(data);}
  }
  static string Encoded(string value){return Convert.ToBase64String(Encoding.Unicode.GetBytes(value+"\0"));}
  void Put(string name,string text){byte[] data=Encoding.Unicode.GetBytes(text+"\0");int error=RegSetValueExW(handle,name,0,1,data,(uint)data.Length);if(error!=0)throw new Win32Exception(error,"Owned probe value write failed.");Value v=Find(name);if(v==null||v.Type!=1||v.DataBase64!=Encoded(text))throw new InvalidOperationException("Owned value readback differs.");}
  public Operation Run(string nonce,string expectedIdentity,string expectedDescriptor){
   if(!writable||String.IsNullOrEmpty(nonce)||nonce.Length!=32)throw new InvalidOperationException("Fixed writable probe and generated nonce required.");
   foreach(char c in nonce)if(!((c>='0'&&c<='9')||(c>='a'&&c<='f')))throw new InvalidOperationException("Invalid probe nonce.");
   Operation r=new Operation{Nonce=nonce,Name="WELA_Probe_"+nonce,BeforeValue="WELA_BEFORE_"+nonce,AfterValue="WELA_AFTER_"+nonce,HandleId="0x"+handle.ToInt64().ToString("x"),CleanupComplete=false,Diagnostic=""};
   r.Before=Read();if(r.Before.Identity!=expectedIdentity||r.Before.DescriptorBase64!=expectedDescriptor)throw new InvalidOperationException("Probe key changed after planning.");
   Descriptor.AssertProbeCapacity(r.Before.Values);
   if(Find(r.Name)!=null)throw new InvalidOperationException("Owned nonce value already exists; refusing overwrite.");
   bool attempted=false;
   try{
    attempted=true;Put(r.Name,r.BeforeValue);
    // Credit only the explicit existing REG_SZ modification, not creation/deletion.
    r.StartedUtc=UtcNow().ToString("o");Put(r.Name,r.AfterValue);r.WriteReturnedUtc=UtcNow().ToString("o");
    Snapshot during=Read();if(during.DescriptorBase64!=r.Before.DescriptorBase64)throw new InvalidOperationException("Probe key security changed.");
    r.CompletedUtc=UtcNow().ToString("o");r.Succeeded=true;
   }catch(Exception e){r.Diagnostic=e.ToString();}
   finally{
    try{
     Value owned=Find(r.Name);
     if(owned!=null){if(!attempted||owned.Type!=1||(owned.DataBase64!=Encoded(r.BeforeValue)&&owned.DataBase64!=Encoded(r.AfterValue)))throw new InvalidOperationException("Owned probe value drifted; refusing deletion.");int error=RegDeleteValueW(handle,r.Name);if(error!=0)throw new Win32Exception(error,"Owned probe cleanup failed.");}
     if(Find(r.Name)!=null)throw new InvalidOperationException("Owned probe value remains.");
     r.After=Read();if(r.After.DescriptorBase64!=r.Before.DescriptorBase64||!SameValues(r.Before.Values,r.After.Values))throw new InvalidOperationException("Probe changed unrelated values or key security.");
     r.CleanupComplete=true;
    }catch(Exception e){r.Diagnostic+=" Cleanup: "+e.ToString();r.Succeeded=false;}
   }
   return r;
  }
  public void Dispose(){try{for(int i=keys.Count-1;i>=0;i--)RegCloseKey(keys[i]);keys.Clear();handle=IntPtr.Zero;}finally{if(privilege!=null){privilege.Dispose();privilege=null;}}}
 }
 public sealed class Group { public string Sid; public uint Attributes; }
 public sealed class TokenPrivilege { public string Luid; public uint Attributes; }
 public sealed class Token {
  public string Sid, Name, AuthenticationId, AuthenticationType, ImpersonationLevel, TokenSource;
  public Group[] Groups; public TokenPrivilege[] Privileges;
 }
 public static class TokenReader {
  [DllImport("kernel32.dll",ExactSpelling=true)] static extern void GetSystemTimePreciseAsFileTime(out long value);
  public static DateTime UtcNow() {long value;GetSystemTimePreciseAsFileTime(out value);return DateTime.FromFileTimeUtc(value);}
  [StructLayout(LayoutKind.Sequential)] struct Luid {public uint Low; public int High;}
  [StructLayout(LayoutKind.Sequential)] struct Statistics {public Luid TokenId,AuthenticationId;public long Expiration;public int Type,Level;public uint Charged,Available,Groups,Privileges;public Luid Modified;}
  [StructLayout(LayoutKind.Sequential)] struct SidAndAttributes {public IntPtr Sid;public uint Attributes;}
  [StructLayout(LayoutKind.Sequential)] struct TokenGroups {public uint Count;public SidAndAttributes First;}
  [StructLayout(LayoutKind.Sequential)] struct LuidAndAttributes {public Luid Luid;public uint Attributes;}
  [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
  [DllImport("kernel32.dll")] static extern IntPtr GetCurrentThread();
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr h);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr p,uint access,out IntPtr t);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenThreadToken(IntPtr p,uint access,bool self,out IntPtr t);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetTokenInformation(IntPtr t,int cls,IntPtr data,int length,out int needed);
  static string Hex(Luid id) {return "0x"+(((ulong)(uint)id.High<<32)|id.Low).ToString("x");}
  static IntPtr Read(IntPtr token,int cls,out int length) {
   GetTokenInformation(token,cls,IntPtr.Zero,0,out length);
   if(Marshal.GetLastWin32Error()!=122||length<4||length>65536)throw new InvalidOperationException("Unknown or oversized token information.");
   IntPtr data=Marshal.AllocHGlobal(length);
   if(!GetTokenInformation(token,cls,data,length,out length)){int error=Marshal.GetLastWin32Error();Marshal.FreeHGlobal(data);throw new Win32Exception(error);}
   return data;
  }
  static Token ReadToken(IntPtr token,string source) {
    Token result=new Token();result.TokenSource=source;using(WindowsIdentity identity=new WindowsIdentity(token)){result.Sid=identity.User.Value;result.Name=identity.Name;result.AuthenticationType=identity.AuthenticationType;result.ImpersonationLevel=identity.ImpersonationLevel.ToString();}
    int length;IntPtr p=Read(token,10,out length);
    try {if(length<Marshal.SizeOf(typeof(Statistics)))throw new InvalidOperationException("Truncated token statistics.");result.AuthenticationId=Hex(((Statistics)Marshal.PtrToStructure(p,typeof(Statistics))).AuthenticationId);}finally{Marshal.FreeHGlobal(p);}
    p=Read(token,2,out length);
    try {int count=Marshal.ReadInt32(p),offset=(int)Marshal.OffsetOf(typeof(TokenGroups),"First"),size=Marshal.SizeOf(typeof(SidAndAttributes));if(count<0||count>4096||offset+(long)count*size>length)throw new InvalidOperationException("Invalid token groups.");List<Group> groups=new List<Group>();for(int i=0;i<count;i++){SidAndAttributes g=(SidAndAttributes)Marshal.PtrToStructure(IntPtr.Add(p,offset+i*size),typeof(SidAndAttributes));groups.Add(new Group{Sid=new SecurityIdentifier(g.Sid).Value,Attributes=g.Attributes});}groups.Sort((a,b)=>String.CompareOrdinal(a.Sid,b.Sid));result.Groups=groups.ToArray();}finally{Marshal.FreeHGlobal(p);}
    p=Read(token,3,out length);
    try {int count=Marshal.ReadInt32(p),size=Marshal.SizeOf(typeof(LuidAndAttributes));if(count<0||count>4096||4+(long)count*size>length)throw new InvalidOperationException("Invalid token privileges.");List<TokenPrivilege> privileges=new List<TokenPrivilege>();for(int i=0;i<count;i++){LuidAndAttributes v=(LuidAndAttributes)Marshal.PtrToStructure(IntPtr.Add(p,4+i*size),typeof(LuidAndAttributes));privileges.Add(new TokenPrivilege{Luid=Hex(v.Luid),Attributes=v.Attributes});}privileges.Sort((a,b)=>String.CompareOrdinal(a.Luid,b.Luid));result.Privileges=privileges.ToArray();}finally{Marshal.FreeHGlobal(p);}
    return result;
  }
  [DllImport("advapi32.dll")] static extern bool IsTokenRestricted(IntPtr token);
  public static Token Snapshot() {
   IntPtr thread=IntPtr.Zero,process=IntPtr.Zero;
   if(!OpenThreadToken(GetCurrentThread(),8,true,out thread)){int error=Marshal.GetLastWin32Error();if(error!=1008)throw new Win32Exception(error);}
   try {
    if(!OpenProcessToken(GetCurrentProcess(),8,out process))throw new Win32Exception(Marshal.GetLastWin32Error());
    if(IsTokenRestricted(process)||(thread!=IntPtr.Zero&&IsTokenRestricted(thread)))throw new InvalidOperationException("Restricted tokens are unsupported.");
    Token primary=ReadToken(process,"Process");
    if(thread!=IntPtr.Zero)throw new InvalidOperationException("Impersonated recovery is unsupported.");
    return primary;
   } finally {if(process!=IntPtr.Zero)CloseHandle(process);if(thread!=IntPtr.Zero)CloseHandle(thread);}
  }
 }
}
