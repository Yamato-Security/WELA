// Disposable CI fixture only. Never imported by WELA product code.
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32;
namespace Wela.RegistrySaclFixture {
 sealed class Privilege : IDisposable {
  [StructLayout(LayoutKind.Sequential)] struct Luid {public uint Low;public int High;}
  [StructLayout(LayoutKind.Sequential)] struct Privileges {public uint Count;public Luid Id;public uint Attributes;}
  [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
  [DllImport("kernel32.dll")] static extern IntPtr GetCurrentThread();
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenThreadToken(IntPtr thread,uint access,bool self,out IntPtr token);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool LookupPrivilegeValue(string system,string name,out Luid luid);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool AdjustTokenPrivileges(IntPtr token,bool all,ref Privileges requested,uint size,out Privileges previous,out uint required);
  IntPtr token;Privileges previous;
  public Privilege(string name){
   if(name!="SeBackupPrivilege"&&name!="SeRestorePrivilege")throw new InvalidOperationException("Unreviewed fixture privilege.");
   IntPtr thread;if(OpenThreadToken(GetCurrentThread(),8,true,out thread)){CloseHandle(thread);throw new InvalidOperationException("Impersonated fixture refused.");}int error=Marshal.GetLastWin32Error();if(error!=1008)throw new Win32Exception(error);
   if(!OpenProcessToken(GetCurrentProcess(),0x28,out token))throw new Win32Exception(Marshal.GetLastWin32Error());
   try{Luid id;if(!LookupPrivilegeValue(null,name,out id))throw new Win32Exception(Marshal.GetLastWin32Error());Privileges request=new Privileges{Count=1,Id=id,Attributes=2};uint needed;bool ok=AdjustTokenPrivileges(token,false,ref request,(uint)Marshal.SizeOf(typeof(Privileges)),out previous,out needed);error=Marshal.GetLastWin32Error();if(!ok||error!=0)throw new Win32Exception(error,"Existing fixture privilege is required: "+name);}catch{CloseHandle(token);token=IntPtr.Zero;throw;}
  }
  public void Dispose(){if(token==IntPtr.Zero)return;try{Privileges ignored;uint needed;bool ok=AdjustTokenPrivileges(token,false,ref previous,(uint)Marshal.SizeOf(typeof(Privileges)),out ignored,out needed);int error=Marshal.GetLastWin32Error();if(!ok||error!=0)throw new Win32Exception(error,"Fixture privilege restoration failed.");}finally{CloseHandle(token);token=IntPtr.Zero;}}
 }
 public sealed class WriteReceipt {public string StartedUtc,ReturnedUtc,CompletedUtc,HandleId,ValueName,Value;public int Calls;public bool Success;}
 public sealed class Hive : IDisposable {
  [DllImport("kernel32.dll",ExactSpelling=true)] static extern void GetSystemTimePreciseAsFileTime(out long value);
  static DateTime UtcNow(){long value;GetSystemTimePreciseAsFileTime(out value);return DateTime.FromFileTimeUtc(value);}
  static readonly IntPtr HKCU=new IntPtr(unchecked((int)0x80000001)),HKU=new IntPtr(unchecked((int)0x80000003));
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] static extern int RegCreateKeyExW(IntPtr root,string path,int reserved,string cls,uint options,uint access,IntPtr security,out IntPtr result,out uint disposition);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] static extern int RegOpenKeyExW(IntPtr root,string path,uint options,uint access,out IntPtr key);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] static extern int RegSetValueExW(IntPtr key,string name,uint reserved,uint type,byte[] data,uint size);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] static extern int RegQueryValueExW(IntPtr key,string name,IntPtr reserved,out uint type,byte[] data,ref uint size);
  [DllImport("advapi32.dll")] static extern int RegCloseKey(IntPtr key);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] static extern int RegSaveKeyExW(IntPtr key,string file,IntPtr security,uint flags);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] static extern int RegLoadKeyW(IntPtr root,string name,string file);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] static extern int RegUnLoadKeyW(IntPtr root,string name);
  public readonly string Nonce,Sid,SeedPath,FilePath;
  public bool SeedCreated{get;private set;} public bool Saved{get;private set;} public bool Loaded{get;private set;}
  public Hive(string nonce,string file){
   if(!System.Text.RegularExpressions.Regex.IsMatch(nonce??"","^[a-f0-9]{32}$"))throw new InvalidOperationException("Exact fixture nonce required.");
   Nonce=nonce;Sid="S-1-5-21-"+Convert.ToUInt32(nonce.Substring(0,8),16)+"-"+Convert.ToUInt32(nonce.Substring(8,8),16)+"-"+Convert.ToUInt32(nonce.Substring(16,8),16)+"-1001";
   SeedPath="Software\\WELARegistrySaclSeed_"+nonce;FilePath=Path.GetFullPath(file);
   if(File.Exists(FilePath))throw new InvalidOperationException("Fixture hive file must be new.");
  }
  static void Check(int status,string operation){if(status!=0)throw new Win32Exception(status,operation);}
  static bool Exists(RegistryKey root,string name){using(RegistryKey key=root.OpenSubKey(name)){return key!=null;}}
  public void Prepare(){
   if(SeedCreated||Saved||Loaded||Exists(Registry.Users,Sid))throw new InvalidOperationException("Fixture identity already exists.");
   IntPtr key;uint disposition;Check(RegCreateKeyExW(HKCU,SeedPath,0,null,0,0xF003F,IntPtr.Zero,out key,out disposition),"Create owned seed");
   try{if(disposition!=1)throw new InvalidOperationException("Seed collided with an existing key.");SeedCreated=true;
    using(RegistryKey seed=Registry.CurrentUser.OpenSubKey(SeedPath,true)){seed.SetValue("WelaFixtureOwner",Nonce,RegistryValueKind.String);seed.Flush();}
    using(new Privilege("SeBackupPrivilege")){Check(RegSaveKeyExW(key,FilePath,IntPtr.Zero,2),"Save owned seed to a new hive file");Saved=true;}
   }finally{RegCloseKey(key);}
   if(Exists(Registry.Users,Sid))throw new InvalidOperationException("Fixture HKU mount collided.");
   using(new Privilege("SeBackupPrivilege"))using(new Privilege("SeRestorePrivilege")){Check(RegLoadKeyW(HKU,Sid,FilePath),"Load owned hive under its fresh SID");Loaded=true;}
   AssertOwned();
  }
  public void AssertOwned(){using(RegistryKey key=Registry.Users.OpenSubKey(Sid)){if(!Loaded||key==null||key.GetValueKind("WelaFixtureOwner")!=RegistryValueKind.String||!String.Equals(key.GetValue("WelaFixtureOwner") as string,Nonce,StringComparison.Ordinal))throw new InvalidOperationException("Owned hive marker changed.");}}
  public void CreateRunOnce(){AssertOwned();IntPtr key;uint disposition;Check(RegCreateKeyExW(HKU,Sid+"\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",0,null,0,0xF003F,IntPtr.Zero,out key,out disposition),"Create owned catalog RunOnce target");try{if(disposition!=1)throw new InvalidOperationException("Owned target unexpectedly exists.");}finally{RegCloseKey(key);}
   using(RegistryKey target=Registry.Users.OpenSubKey(Sid+"\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",true)){target.SetValue("KeepTypedDword",321,RegistryValueKind.DWord);}
  }
  public void AssertValues(bool probe){using(RegistryKey key=Registry.Users.OpenSubKey(Sid+"\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce")){if(key==null||key.ValueCount!=(probe?2:1)||key.GetValueKind("KeepTypedDword")!=RegistryValueKind.DWord||!(key.GetValue("KeepTypedDword") is int)||(int)key.GetValue("KeepTypedDword")!=321)throw new InvalidOperationException("Unrelated owned typed values changed.");if(probe&&(key.GetValueKind("WelaProbe_"+Nonce)!=RegistryValueKind.String||!String.Equals(key.GetValue("WelaProbe_"+Nonce) as string,Nonce,StringComparison.Ordinal)))throw new InvalidOperationException("Owned nonce value mismatch.");}}
  public WriteReceipt WriteProbe(){
   AssertOwned();AssertValues(false);string name="WelaProbe_"+Nonce;IntPtr key;
   Check(RegOpenKeyExW(HKU,Sid+"\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",0,0x103,out key),"Open owned value writer");
   try{
    byte[] bytes=System.Text.Encoding.Unicode.GetBytes(Nonce+"\0");string handle="0x"+unchecked((ulong)key.ToInt64()).ToString("x");
    DateTime start=UtcNow();Check(RegSetValueExW(key,name,0,1,bytes,(uint)bytes.Length),"Write one owned nonce REG_SZ");DateTime returned=UtcNow();
    uint type,size=(uint)bytes.Length;byte[] actual=new byte[size];Check(RegQueryValueExW(key,name,IntPtr.Zero,out type,actual,ref size),"Read back same-handle owned nonce");
    if(type!=1||size!=bytes.Length||Convert.ToBase64String(actual)!=Convert.ToBase64String(bytes))throw new InvalidOperationException("Probe write readback failed.");DateTime completed=UtcNow();
    return new WriteReceipt{StartedUtc=start.ToString("o"),ReturnedUtc=returned.ToString("o"),CompletedUtc=completed.ToString("o"),HandleId=handle,ValueName=name,Value=Nonce,Calls=1,Success=true};
   }finally{RegCloseKey(key);}
  }
  public void Dispose(){
   if(Loaded){AssertOwned();using(new Privilege("SeBackupPrivilege"))using(new Privilege("SeRestorePrivilege")){Check(RegUnLoadKeyW(HKU,Sid),"Unload owned fixture hive");Loaded=false;}}
   if(SeedCreated){using(RegistryKey seed=Registry.CurrentUser.OpenSubKey(SeedPath)){if(seed==null||seed.SubKeyCount!=0||seed.ValueCount!=1||seed.GetValueKind("WelaFixtureOwner")!=RegistryValueKind.String||!String.Equals(seed.GetValue("WelaFixtureOwner") as string,Nonce,StringComparison.Ordinal))throw new InvalidOperationException("Owned seed changed; refuse deletion.");}Registry.CurrentUser.DeleteSubKey(SeedPath,true);SeedCreated=false;}
  }
 }
}
