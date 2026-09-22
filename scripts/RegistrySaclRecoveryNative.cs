// Empty-key registry recovery: remove one proven explicit selected-root audit ACE.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
namespace Wela.RegistrySaclRecovery {
 public sealed class Ace { public string Binary; public int Type,Flags,Mask; public string Sid; public bool Ordinary; }
 public sealed class Snapshot {
  public string Path,Kind,Identity; public bool IsDirectory;
  public string DescriptorBase64,Owner,Group,DaclBase64; public int ControlFlags,SecurityInformation;
  public string DescriptorScope; public Ace[] Aces;
 }
 public static class Descriptor {
  public const string SourceSha256="__WELA_REGISTRY_SACL_RECOVERY_SOURCE_SHA256__";
  public static string Bytes(GenericAcl value) { if(value==null)return null;byte[] b=new byte[value.BinaryLength];value.GetBinaryForm(b,0);return Convert.ToBase64String(b); }
  public static string Bytes(GenericAce value) { byte[] b=new byte[value.BinaryLength];value.GetBinaryForm(b,0);return Convert.ToBase64String(b); }
  static string Sid(SecurityIdentifier value) {return value==null?null:value.Value;}
  public static RawSecurityDescriptor Parse(string value) {
   byte[] b=Convert.FromBase64String(value);
   if(b.Length<20||b.Length>1048576||Convert.ToBase64String(b)!=value)throw new InvalidOperationException("Invalid or noncanonical descriptor bytes.");
   RawSecurityDescriptor sd=new RawSecurityDescriptor(b,0);
   return sd;
  }
  static Dictionary<string,int> Counts(RawAcl acl) {
   Dictionary<string,int> counts=new Dictionary<string,int>(StringComparer.Ordinal);
   if(acl!=null)foreach(GenericAce ace in acl){string b=Bytes(ace);if(!counts.ContainsKey(b))counts[b]=0;counts[b]++;}
   return counts;
  }
  static void Outside(RawSecurityDescriptor before,RawSecurityDescriptor after,bool allowPresence) {
   int mask=allowPresence?~16:~0;
   if(Sid(before.Owner)!=Sid(after.Owner)||Sid(before.Group)!=Sid(after.Group)||Bytes(before.DiscretionaryAcl)!=Bytes(after.DiscretionaryAcl)||before.ResourceManagerControl!=after.ResourceManagerControl||(((int)before.ControlFlags)&mask)!=(((int)after.ControlFlags)&mask))throw new InvalidOperationException("Owner, group, DACL or preserved control/header fields differ.");
  }
  public static string AddedAce(string beforeBytes,string afterBytes,string sid,int mask,int flags) {
   if((sid!="S-1-1-0"&&sid!="S-1-5-11")||mask<=0||(flags!=64&&flags!=128&&flags!=192&&flags!=66&&flags!=130&&flags!=194))throw new InvalidOperationException("Only an explicit ordinary selected-root audit ACE is supported.");
   RawSecurityDescriptor before=Parse(beforeBytes),after=Parse(afterBytes);Outside(before,after,true);
   if(after.SystemAcl==null||after.SystemAcl.Revision!=(before.SystemAcl==null?2:before.SystemAcl.Revision))throw new InvalidOperationException("SACL revision changed during the claimed addition.");
   if(before.SystemAcl!=null)foreach(GenericAce entry in before.SystemAcl){CommonAce common=entry as CommonAce;if(common!=null&&!common.IsCallback&&common.AceType==AceType.SystemAudit&&common.SecurityIdentifier.Value==sid&&(int)common.AceFlags==flags&&(common.AccessMask&mask)==mask)throw new InvalidOperationException("Original descriptor already covered the requested audit ACE.");}
   string added=Bytes(new CommonAce((AceFlags)flags,AceQualifier.SystemAudit,mask,new SecurityIdentifier(sid),false,null));
   Dictionary<string,int> remaining=Counts(after.SystemAcl);
   if(!remaining.ContainsKey(added)||remaining[added]!=1)throw new InvalidOperationException("Expected exactly one new matching audit ACE.");
   remaining[added]--;
   if(before.SystemAcl!=null)foreach(GenericAce entry in before.SystemAcl){string b=Bytes(entry);if(!remaining.ContainsKey(b)||remaining[b]<1)throw new InvalidOperationException("An original ACE was changed or removed.");remaining[b]--;}
   foreach(int count in remaining.Values)if(count!=0)throw new InvalidOperationException("The completed operation changed more than one audit ACE.");
   int oldCount=before.SystemAcl==null?0:before.SystemAcl.Count;for(int i=0;i<oldCount;i++)if(Bytes(before.SystemAcl[i])!=Bytes(after.SystemAcl[i]))throw new InvalidOperationException("Original ACE ordering changed.");if(Bytes(after.SystemAcl[oldCount])!=added)throw new InvalidOperationException("The selected audit ACE was not the single append.");
   return added;
  }
  public static void Removed(string beforeBytes,string afterBytes,string added) {
   RawSecurityDescriptor before=Parse(beforeBytes),after=Parse(afterBytes);Outside(before,after,false);
   if(before.SystemAcl==null)throw new InvalidOperationException("Original SACL is absent.");
   if(after.SystemAcl==null){if(before.SystemAcl.Count!=1)throw new InvalidOperationException("A null SACL would lose unrelated audit ACEs.");}
   else if(before.SystemAcl.Revision!=after.SystemAcl.Revision)throw new InvalidOperationException("SACL revision changed during removal: "+before.SystemAcl.Revision+" to "+after.SystemAcl.Revision+" (after count "+after.SystemAcl.Count+").");
   Dictionary<string,int> expected=Counts(before.SystemAcl),actual=Counts(after.SystemAcl);
   if(!expected.ContainsKey(added)||expected[added]!=1)throw new InvalidOperationException("The selected audit ACE is no longer unique.");
   expected[added]--;
   foreach(KeyValuePair<string,int> entry in expected){int count=actual.ContainsKey(entry.Key)?actual[entry.Key]:0;if(count!=entry.Value)throw new InvalidOperationException("Unrelated audit ACEs changed during removal.");actual.Remove(entry.Key);}
   if(actual.Count!=0)throw new InvalidOperationException("Unexpected ACE appeared during removal.");
   List<string> ordered=new List<string>();foreach(GenericAce entry in before.SystemAcl)if(Bytes(entry)!=added)ordered.Add(Bytes(entry));if(after.SystemAcl!=null){for(int i=0;i<ordered.Count;i++)if(Bytes(after.SystemAcl[i])!=ordered[i])throw new InvalidOperationException("Unrelated audit ACE order changed during removal.");}
  }
  public static string SaclRepresentation(string value) {
   RawSecurityDescriptor sd=Parse(value);bool present=(sd.ControlFlags&ControlFlags.SystemAclPresent)!=0;
   if(!present)return "Absent";
   if(sd.SystemAcl==null)return "PresentNull";
   return (sd.SystemAcl.Count==0?"PresentEmpty":"PresentWithAces")+";Revision="+sd.SystemAcl.Revision;
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
  [DllImport("advapi32.dll")] static extern uint SetSecurityInfo(IntPtr handle,uint kind,uint flags,IntPtr owner,IntPtr group,IntPtr dacl,IntPtr sacl);
  readonly string path,nativePath;readonly List<IntPtr> keys=new List<IntPtr>();IntPtr handle;Privilege privilege;
  public bool WriteAttempted {get;private set;}public Snapshot AfterObservation {get;private set;}
  public Target(string path){
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
     IntPtr opened;int error=RegOpenKeyExW(current,parts[i],8,0x01020101U|(i==parts.Length-1?8U:0U),out opened);
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
   AssertEmpty();if(Check()!=identity)throw new InvalidOperationException("Registry last-write identity changed during observation.");return Descriptor.Observe(path,identity,bytes);
  }
  public Snapshot Remove(string expectedIdentity,string expectedDescriptor,string added){
   Snapshot before=Read();if(before.Identity!=expectedIdentity||before.DescriptorBase64!=expectedDescriptor)throw new InvalidOperationException("Reviewed registry identity or descriptor changed before removal.");
   RawSecurityDescriptor sd=Descriptor.Parse(before.DescriptorBase64);int index=-1;
   if(sd.SystemAcl!=null)for(int i=0;i<sd.SystemAcl.Count;i++)if(Descriptor.Bytes(sd.SystemAcl[i])==added){if(index!=-1)throw new InvalidOperationException("Audit ACE is not unique.");index=i;}
   if(index<0)throw new InvalidOperationException("Audit ACE is absent.");CommonAce ace=sd.SystemAcl[index] as CommonAce;
   if(ace==null||ace.IsCallback||ace.AceType!=AceType.SystemAudit||((int)ace.AceFlags!=64&&(int)ace.AceFlags!=128&&(int)ace.AceFlags!=192&&(int)ace.AceFlags!=66&&(int)ace.AceFlags!=130&&(int)ace.AceFlags!=194))throw new InvalidOperationException("Only the proven explicit selected-root audit ACE can be removed.");
   sd.SystemAcl.RemoveAce(index);byte[] bytes=new byte[sd.SystemAcl.BinaryLength];sd.SystemAcl.GetBinaryForm(bytes,0);IntPtr buffer=Marshal.AllocHGlobal(bytes.Length);
   try{
    Marshal.Copy(bytes,0,buffer,bytes.Length);Snapshot last=Read();if(last.Identity!=expectedIdentity||last.DescriptorBase64!=expectedDescriptor)throw new InvalidOperationException("Registry changed immediately before removal.");
    WriteAttempted=true;uint error=SetSecurityInfo(handle,4,8,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,buffer);if(error!=0)throw new Win32Exception((int)error,"SACL-only registry removal failed.");
   }finally{Marshal.FreeHGlobal(buffer);}
   Snapshot after=Read();AfterObservation=after;Descriptor.Removed(before.DescriptorBase64,after.DescriptorBase64,added);return after;
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
