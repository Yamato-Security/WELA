// Disposable hosted-test setup only. Never imported by WELA product commands.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
namespace Wela.FileSaclFixture {
 public sealed class ValueState {public string Name,Kind;public object Value;}
 public sealed class KeyState {public string Name;public ValueState[] Values;public KeyState[] Children;}
 public sealed class Profile : IDisposable {
  const string ProfileList=@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";
  const string ShellFolders=@"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders";
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] static extern int RegCreateKeyExW(IntPtr root,string path,int reserved,string cls,uint options,uint access,IntPtr security,out IntPtr result,out uint disposition);
  [DllImport("advapi32.dll")] static extern int RegCloseKey(IntPtr key);
  public readonly string Nonce,Sid,Root,ProfilePath,AppDataPath;
  public bool Created {get;private set;}
  public Profile(string nonce,string sid,string root) {
   if(Environment.OSVersion.Platform!=PlatformID.Win32NT||!Environment.Is64BitProcess||Environment.GetEnvironmentVariable("GITHUB_ACTIONS")!="true"||Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT")!="github-hosted")throw new InvalidOperationException("Disposable native hosted Windows fixture only.");
   if(!System.Text.RegularExpressions.Regex.IsMatch(nonce??"","^[a-f0-9]{32}$"))throw new InvalidOperationException("Exact owned nonce required.");
   string expectedSid="S-1-5-21-"+Convert.ToUInt32(nonce.Substring(0,8),16)+"-"+Convert.ToUInt32(nonce.Substring(8,8),16)+"-"+Convert.ToUInt32(nonce.Substring(16,8),16)+"-1001";
   if(sid!=expectedSid)throw new InvalidOperationException("Profile must use the matching owned hive SID.");
   string expectedRoot=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),"Temp","wela-filesystem-sacl-"+nonce);
   if(!String.Equals(Path.GetFullPath(root),expectedRoot,StringComparison.OrdinalIgnoreCase))throw new InvalidOperationException("Only the nonce-owned system-volume fixture tree is supported.");
   AssertOrdinary(root);Nonce=nonce;Sid=sid;Root=Path.GetFullPath(root);ProfilePath=Path.Combine(Root,"Profile");AppDataPath=Path.Combine(Root,"RedirectedRoaming");
  }
  static void AssertOrdinary(string path) {
   for(DirectoryInfo directory=new DirectoryInfo(path);directory!=null;directory=directory.Parent)
    if(!directory.Exists||(directory.Attributes&FileAttributes.ReparsePoint)!=0)throw new InvalidOperationException("Fixture tree or ancestor is absent or a reparse point.");
  }
  public static KeyState Snapshot() {
   int count=0;using(RegistryKey machine=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,RegistryView.Registry64))
   using(RegistryKey root=machine.OpenSubKey(ProfileList,false)){if(root==null)throw new InvalidOperationException("Actual ProfileList is missing.");return Read(root,"ProfileList",0,ref count);}
  }
  static KeyState Read(RegistryKey key,string name,int depth,ref int count) {
   if(depth>8||++count>4096)throw new InvalidOperationException("Profile inventory exceeds its bounded scope.");
   string[] names=key.GetValueNames();Array.Sort(names,StringComparer.Ordinal);if(names.Length>256)throw new InvalidOperationException("Profile values exceed fixture bound.");
   var values=new List<ValueState>();foreach(string valueName in names){
    RegistryValueKind kind=key.GetValueKind(valueName);object value=key.GetValue(valueName,null,RegistryValueOptions.DoNotExpandEnvironmentNames);
    if(value==null||kind==RegistryValueKind.Unknown||kind==RegistryValueKind.None)throw new InvalidOperationException("Unknown typed profile value.");
    if(value is string&&((string)value).Length>1048576||value is byte[]&&((byte[])value).Length>1048576)throw new InvalidOperationException("Profile value exceeds fixture bound.");
    values.Add(new ValueState{Name=valueName,Kind=kind.ToString(),Value=value});
   }
   string[] children=key.GetSubKeyNames();Array.Sort(children,StringComparer.Ordinal);var result=new List<KeyState>();
   foreach(string child in children)using(RegistryKey opened=key.OpenSubKey(child,false)){if(opened==null)throw new InvalidOperationException("Profile inventory changed.");result.Add(Read(opened,child,depth+1,ref count));}
   return new KeyState{Name=name,Values=values.ToArray(),Children=result.ToArray()};
  }
  void AssertHive() {
   using(RegistryKey hive=Registry.Users.OpenSubKey(Sid,false))
    if(hive==null||hive.GetValueKind("WelaFixtureOwner")!=RegistryValueKind.String||!String.Equals(hive.GetValue("WelaFixtureOwner") as string,Nonce,StringComparison.Ordinal))throw new InvalidOperationException("Owned hive marker differs.");
  }
  public void Prepare() {
   if(Created)throw new InvalidOperationException("Profile was already prepared.");AssertHive();AssertOrdinary(Root);
   Directory.CreateDirectory(ProfilePath);Directory.CreateDirectory(AppDataPath);
   IntPtr handle;uint disposition;int error=RegCreateKeyExW(new IntPtr(unchecked((int)0x80000002)),ProfileList+"\\"+Sid,0,null,0,0xF013F,IntPtr.Zero,out handle,out disposition);
   if(error!=0)throw new Win32Exception(error,"Create owned ProfileList entry");
   try{
    if(disposition!=1)throw new InvalidOperationException("ProfileList identity already exists.");Created=true;
    using(var safe=new SafeRegistryHandle(handle,false))using(RegistryKey key=RegistryKey.FromHandle(safe,RegistryView.Registry64)){
     key.SetValue("WelaFixtureOwner",Nonce,RegistryValueKind.String);
     key.SetValue("ProfileImagePath",ProfilePath,RegistryValueKind.ExpandString);key.Flush();
    }
   }finally{RegCloseKey(handle);}
   AssertHive();
   using(RegistryKey hive=Registry.Users.OpenSubKey(Sid,true))using(RegistryKey shell=hive.CreateSubKey(ShellFolders)){
    if(shell.ValueCount!=0||shell.SubKeyCount!=0)throw new InvalidOperationException("Owned known-folder key unexpectedly contains data.");
    shell.SetValue("AppData",AppDataPath,RegistryValueKind.ExpandString);
    shell.SetValue("Startup",@"%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",RegistryValueKind.ExpandString);shell.Flush();
   }
   AssertOwned();
  }
  public void AssertOwned() {
   AssertHive();
   using(RegistryKey machine=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,RegistryView.Registry64))
   using(RegistryKey key=machine.OpenSubKey(ProfileList+"\\"+Sid,false)){
    if(!Created||key==null||key.SubKeyCount!=0||key.ValueCount!=2||key.GetValueKind("WelaFixtureOwner")!=RegistryValueKind.String||!String.Equals(key.GetValue("WelaFixtureOwner") as string,Nonce,StringComparison.Ordinal)||key.GetValueKind("ProfileImagePath")!=RegistryValueKind.ExpandString||!String.Equals(key.GetValue("ProfileImagePath",null,RegistryValueOptions.DoNotExpandEnvironmentNames) as string,ProfilePath,StringComparison.Ordinal))throw new InvalidOperationException("Owned ProfileList entry changed; removal is refused.");
   }
  }
  public void Dispose() {
   if(!Created)return;AssertOwned();
   using(RegistryKey machine=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,RegistryView.Registry64))
   using(RegistryKey root=machine.OpenSubKey(ProfileList,true)){root.DeleteSubKey(Sid,true);Created=false;}
  }
 }
}
