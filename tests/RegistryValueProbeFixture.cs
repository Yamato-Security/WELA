// Disposable CI only: creates the fixed diagnostic parent only if absent.
using System;using System.ComponentModel;using System.Runtime.InteropServices;using Microsoft.Win32;
namespace Wela.RegistryValueProbeFixture {
 public sealed class Owner : IDisposable {
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] static extern int RegCreateKeyExW(IntPtr root,string path,uint reserved,string cls,uint options,uint access,IntPtr security,out IntPtr key,out uint disposition);
  [DllImport("advapi32.dll")] static extern int RegCloseKey(IntPtr key);
  readonly string nonce;bool owned;
  public Owner(string nonce){this.nonce=nonce;}
  public void Create(){
   IntPtr key;uint disposition;int error=RegCreateKeyExW(new IntPtr(unchecked((int)0x80000001)),"Software\\WELA",0,null,0,0xF003F,IntPtr.Zero,out key,out disposition);
   if(error!=0)throw new Win32Exception(error);try{if(disposition!=1)throw new InvalidOperationException("Existing WELA key is not disposable fixture property.");owned=true;}finally{RegCloseKey(key);}
   using(RegistryKey p=Registry.CurrentUser.OpenSubKey("Software\\WELA",true)){p.SetValue("FixtureOwner",nonce,RegistryValueKind.String);using(RegistryKey c=p.CreateSubKey("AuditProbe")){c.SetValue("KeepTypedDword",321,RegistryValueKind.DWord);}}
  }
  public void Dispose(){if(!owned)return;
   using(RegistryKey p=Registry.CurrentUser.OpenSubKey("Software\\WELA")){
    if(p==null||p.ValueCount!=1||p.SubKeyCount!=1||p.GetValueKind("FixtureOwner")!=RegistryValueKind.String||(string)p.GetValue("FixtureOwner")!=nonce)throw new InvalidOperationException("Fixture parent drift; no deletion.");
    using(RegistryKey c=p.OpenSubKey("AuditProbe")){if(c==null||c.SubKeyCount!=0||c.ValueCount!=1||c.GetValueKind("KeepTypedDword")!=RegistryValueKind.DWord||(int)c.GetValue("KeepTypedDword")!=321)throw new InvalidOperationException("Fixture child drift or probe residue; no deletion.");}
   }
   Registry.CurrentUser.DeleteSubKey("Software\\WELA\\AuditProbe",true);Registry.CurrentUser.DeleteSubKey("Software\\WELA",true);owned=false;
  }
 }
}
