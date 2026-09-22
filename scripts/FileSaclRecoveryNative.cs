// Narrow leaf-file recovery: remove one proven explicit ordinary audit ACE.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
namespace Wela.FileSaclRecovery {
 public sealed class Ace { public string Binary; public int Type,Flags,Mask; public string Sid; public bool Ordinary; }
 public sealed class Snapshot {
  public string Path,Kind,Identity; public bool IsDirectory;
  public string DescriptorBase64,Owner,Group,DaclBase64; public int ControlFlags,SecurityInformation;
  public string DescriptorScope; public Ace[] Aces;
 }
 public static class Descriptor {
  public const string SourceSha256="__WELA_FILE_SACL_RECOVERY_SOURCE_SHA256__";
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
   if((sid!="S-1-1-0"&&sid!="S-1-5-11")||mask<=0||(flags!=64&&flags!=128&&flags!=192))throw new InvalidOperationException("Only an explicit ordinary non-inherited selected audit ACE is supported.");
   RawSecurityDescriptor before=Parse(beforeBytes),after=Parse(afterBytes);Outside(before,after,true);
   if(after.SystemAcl==null||after.SystemAcl.Revision!=(before.SystemAcl==null?2:before.SystemAcl.Revision))throw new InvalidOperationException("SACL revision changed during the claimed addition.");
   if(before.SystemAcl!=null)foreach(GenericAce entry in before.SystemAcl){CommonAce common=entry as CommonAce;if(common!=null&&!common.IsCallback&&common.AceType==AceType.SystemAudit&&common.SecurityIdentifier.Value==sid&&(int)common.AceFlags==flags&&(common.AccessMask&mask)==mask)throw new InvalidOperationException("Original descriptor already covered the requested audit ACE.");}
   string added=Bytes(new CommonAce((AceFlags)flags,AceQualifier.SystemAudit,mask,new SecurityIdentifier(sid),false,null));
   Dictionary<string,int> remaining=Counts(after.SystemAcl);
   if(!remaining.ContainsKey(added)||remaining[added]!=1)throw new InvalidOperationException("Expected exactly one new matching audit ACE.");
   remaining[added]--;
   if(before.SystemAcl!=null)foreach(GenericAce entry in before.SystemAcl){string b=Bytes(entry);if(!remaining.ContainsKey(b)||remaining[b]<1)throw new InvalidOperationException("An original ACE was changed or removed.");remaining[b]--;}
   foreach(int count in remaining.Values)if(count!=0)throw new InvalidOperationException("The completed operation changed more than one audit ACE.");
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
   return new Snapshot {Path=path,Kind="FileSystem",Identity=identity,IsDirectory=false,DescriptorBase64=encoded,Owner=Sid(sd.Owner),Group=Sid(sd.Group),DaclBase64=Bytes(sd.DiscretionaryAcl),ControlFlags=(int)sd.ControlFlags,SecurityInformation=511,DescriptorScope="WinSDK-defined sections 0x1ff; future sections unobserved",Aces=entries.ToArray()};
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
  [StructLayout(LayoutKind.Sequential,Pack=4)] struct FileInfo {public uint Attributes;public long Created,Accessed,Written;public uint Volume,SizeHigh,SizeLow,Links,IndexHigh,IndexLow;}
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateFile(string name,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(IntPtr handle,out FileInfo info);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern uint GetFinalPathNameByHandle(IntPtr handle,StringBuilder path,uint size,uint flags);
  [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr value);
  [DllImport("advapi32.dll")] static extern uint GetSecurityInfo(IntPtr handle,uint kind,uint flags,out IntPtr owner,out IntPtr group,out IntPtr dacl,out IntPtr sacl,out IntPtr descriptor);
  [DllImport("advapi32.dll")] static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
  [DllImport("advapi32.dll")] static extern uint SetSecurityInfo(IntPtr handle,uint kind,uint flags,IntPtr owner,IntPtr group,IntPtr dacl,IntPtr sacl);
  readonly string path;IntPtr handle;Privilege privilege;public bool WriteAttempted {get;private set;}public Snapshot AfterObservation {get;private set;}
  public Target(string path){this.path=path;try{privilege=new Privilege();handle=CreateFile(path,0x01020000,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero);if(handle==new IntPtr(-1)){int error=Marshal.GetLastWin32Error();handle=IntPtr.Zero;throw new Win32Exception(error);}Check();}catch{Dispose();throw;}}
  string Check(){if(handle==IntPtr.Zero)throw new ObjectDisposedException("Target");FileInfo info;if(!GetFileInformationByHandle(handle,out info))throw new Win32Exception(Marshal.GetLastWin32Error());if((info.Attributes&0x410)!=0)throw new InvalidOperationException("Directories and reparse files are unsupported.");StringBuilder final=new StringBuilder(32768);uint length=GetFinalPathNameByHandle(handle,final,(uint)final.Capacity,0);if(length==0||length>=final.Capacity||!String.Equals(final.ToString(),"\\\\?\\"+path,StringComparison.OrdinalIgnoreCase))throw new InvalidOperationException("Final held file path differs from the reviewed path.");return info.Volume+":"+info.IndexHigh+":"+info.IndexLow+":"+info.Created;}
  public Snapshot Read(){string identity=Check();IntPtr owner,group,dacl,sacl,descriptor;uint error=GetSecurityInfo(handle,1,511,out owner,out group,out dacl,out sacl,out descriptor);if(error!=0)throw new Win32Exception((int)error,"Full SDK-defined file descriptor read failed.");byte[] bytes;try{uint size=GetSecurityDescriptorLength(descriptor);if(size<20||size>1048576)throw new InvalidOperationException("Invalid descriptor size.");bytes=new byte[size];Marshal.Copy(descriptor,bytes,0,(int)size);}finally{LocalFree(descriptor);}if(Check()!=identity)throw new InvalidOperationException("Held file identity changed.");return Descriptor.Observe(path,identity,bytes);}
  public Snapshot Remove(string expectedIdentity,string expectedDescriptor,string added){
   Snapshot before=Read();if(before.Identity!=expectedIdentity||before.DescriptorBase64!=expectedDescriptor)throw new InvalidOperationException("Reviewed file identity or descriptor changed before removal.");
   RawSecurityDescriptor sd=Descriptor.Parse(before.DescriptorBase64);int index=-1;
   if(sd.SystemAcl!=null)for(int i=0;i<sd.SystemAcl.Count;i++)if(Descriptor.Bytes(sd.SystemAcl[i])==added){if(index!=-1)throw new InvalidOperationException("Audit ACE is not unique.");index=i;}
   if(index<0)throw new InvalidOperationException("Audit ACE is absent.");CommonAce ace=sd.SystemAcl[index] as CommonAce;
   if(ace==null||ace.IsCallback||ace.AceType!=AceType.SystemAudit||((int)ace.AceFlags!=64&&(int)ace.AceFlags!=128&&(int)ace.AceFlags!=192))throw new InvalidOperationException("Only an explicit ordinary audit ACE can be removed.");
   sd.SystemAcl.RemoveAce(index);byte[] bytes=new byte[sd.SystemAcl.BinaryLength];sd.SystemAcl.GetBinaryForm(bytes,0);IntPtr buffer=Marshal.AllocHGlobal(bytes.Length);
   try{Marshal.Copy(bytes,0,buffer,bytes.Length);WriteAttempted=true;uint error=SetSecurityInfo(handle,1,8,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,buffer);if(error!=0)throw new Win32Exception((int)error,"SACL-only removal failed.");}finally{Marshal.FreeHGlobal(buffer);}
   Snapshot after=Read();AfterObservation=after;if(after.Identity!=before.Identity)throw new InvalidOperationException("File identity changed during removal.");Descriptor.Removed(before.DescriptorBase64,after.DescriptorBase64,added);return after;
  }
  public void Dispose(){try{if(handle!=IntPtr.Zero){CloseHandle(handle);handle=IntPtr.Zero;}}finally{if(privilege!=null){privilege.Dispose();privilege=null;}}}
 }
}
