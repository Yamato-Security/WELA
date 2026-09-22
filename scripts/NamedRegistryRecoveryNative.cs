using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
namespace Wela.NamedRegistryRecovery {
 public sealed class Observation {
  public bool Exists; public int Value; public string ObjectName, OtherValues, Children, Security, LastWrite;
 }
 public sealed class Key : IDisposable {
  public const string SourceSha256 = "__WELA_SOURCE_SHA256__";
  IntPtr handle;
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode)] static extern int RegOpenKeyEx(IntPtr key,string sub,uint options,uint access,out IntPtr result);
  [DllImport("advapi32.dll")] static extern int RegCloseKey(IntPtr key);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode)] static extern int RegQueryValueEx(IntPtr key,string name,IntPtr reserved,out uint type,byte[] data,ref uint size);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode)] static extern int RegEnumValue(IntPtr key,uint index,StringBuilder name,ref uint nameLength,IntPtr reserved,out uint type,byte[] data,ref uint size);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode)] static extern int RegEnumKeyEx(IntPtr key,uint index,StringBuilder name,ref uint nameLength,IntPtr reserved,IntPtr cls,IntPtr clsLength,out long lastWrite);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode)] static extern int RegQueryInfoKey(IntPtr key,IntPtr cls,IntPtr clsLength,IntPtr reserved,out uint subkeys,IntPtr maxSub,IntPtr maxClass,out uint values,IntPtr maxName,IntPtr maxValue,IntPtr security,out long lastWrite);
  [DllImport("advapi32.dll")] static extern int RegGetKeySecurity(IntPtr key,uint information,byte[] descriptor,ref uint size);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode)] static extern int RegSetValueEx(IntPtr key,string name,int reserved,uint type,byte[] data,uint size);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode)] static extern int RegDeleteValue(IntPtr key,string name);
  [DllImport("ntdll.dll")] static extern int NtQueryKey(IntPtr key,int informationClass,byte[] information,int length,out int resultLength);
  static void Check(int error){if(error!=0)throw new Win32Exception(error);}
  static string Hash(byte[] bytes){using(var sha=SHA256.Create())return BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-","").ToLowerInvariant();}
  static string HashStrings(List<string> values){values.Sort(StringComparer.Ordinal);return Hash(Encoding.UTF8.GetBytes(String.Join("\n",values.ToArray())));}
  static string Enc(string value){return Convert.ToBase64String(Encoding.UTF8.GetBytes(value));}
  public Key(string path,bool write) {
   if(!Environment.Is64BitProcess || !path.StartsWith("HKLM:\\SOFTWARE\\",StringComparison.Ordinal) || path.IndexOfAny(new char[]{'/', '*','?','\0'})>=0)throw new InvalidOperationException("Only reviewed native HKLM SOFTWARE paths are supported.");
   string[] parts=path.Substring(6).Split('\\');IntPtr parent=new IntPtr(unchecked((int)0x80000002));bool owned=false;
   try {
    for(int i=0;i<parts.Length;i++) {
     if(parts[i].Length==0 || parts[i]=="." || parts[i]=="..")throw new InvalidOperationException("Ambiguous registry path.");
     IntPtr next;Check(RegOpenKeyEx(parent,parts[i],8,0x20119U | ((write && i==parts.Length-1)?2U:0U),out next));
     if(owned)RegCloseKey(parent);parent=next;owned=true;
     uint type,size=0;int error=RegQueryValueEx(parent,"SymbolicLinkValue",IntPtr.Zero,out type,null,ref size);
     if(error!=0 && error!=2 && error!=234)Check(error);
     if((error==0 || error==234) && type==6)throw new InvalidOperationException("Registry links are unsupported.");
    }
    handle=parent;owned=false;
   } finally {if(owned)RegCloseKey(parent);}
  }
  string Name() {
   int required;int status=NtQueryKey(handle,3,null,0,out required);
   if(status!=unchecked((int)0xC0000023) && status!=unchecked((int)0x80000005))throw new InvalidOperationException("Cannot size native registry identity: "+status);
   if(required<4 || required>65536)throw new InvalidOperationException("Native registry name bound exceeded.");
   byte[] bytes=new byte[required];status=NtQueryKey(handle,3,bytes,bytes.Length,out required);
   if(status!=0)throw new InvalidOperationException("Cannot read native registry identity: "+status);
   int length=BitConverter.ToInt32(bytes,0);if(length<0 || length>bytes.Length-4 || (length%2)!=0)throw new InvalidOperationException("Invalid native registry name.");
   return Encoding.Unicode.GetString(bytes,4,length);
  }
  public Observation Read(string selected) {
   var result=new Observation();result.ObjectName=Name();
   uint subkeys,values;long time;Check(RegQueryInfoKey(handle,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,out subkeys,IntPtr.Zero,IntPtr.Zero,out values,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,out time));
   if(subkeys>256 || values>256)throw new InvalidOperationException("Registry inventory exceeds 256 children/values.");result.LastWrite=time.ToString(System.Globalization.CultureInfo.InvariantCulture);
   var other=new List<string>();long total=0;
   for(uint i=0;i<values;i++) {
    var name=new StringBuilder(16384);uint nameLength=16384,type,size=65536;byte[] data=new byte[size];Check(RegEnumValue(handle,i,name,ref nameLength,IntPtr.Zero,out type,data,ref size));
    total+=size;if(total>1048576)throw new InvalidOperationException("Registry value inventory exceeds one MiB.");Array.Resize(ref data,(int)size);
    if(String.Equals(name.ToString(),selected,StringComparison.OrdinalIgnoreCase)) {
     if(name.ToString()!=selected || type!=4 || size!=4)throw new InvalidOperationException("Selected logging value has an unknown name/type/length.");
     uint value=BitConverter.ToUInt32(data,0);if(value>1)throw new InvalidOperationException("Selected logging DWORD is outside 0/1.");result.Exists=true;result.Value=(int)value;
    } else other.Add(Enc(name.ToString())+"|"+type+"|"+size+"|"+Hash(data));
   }
   result.OtherValues=HashStrings(other);
   var children=new List<string>();
   for(uint i=0;i<subkeys;i++){var name=new StringBuilder(256);uint length=256;long childTime;Check(RegEnumKeyEx(handle,i,name,ref length,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,out childTime));children.Add(Enc(name.ToString()));}
   result.Children=HashStrings(children);
   uint securitySize=0;int code=RegGetKeySecurity(handle,7,null,ref securitySize);if(code!=122)Check(code);
   if(securitySize<20 || securitySize>65536)throw new InvalidOperationException("Registry security descriptor size is unsupported.");
   byte[] security=new byte[securitySize];Check(RegGetKeySecurity(handle,7,security,ref securitySize));Array.Resize(ref security,(int)securitySize);result.Security=Hash(security);
   uint endSubkeys,endValues;long endTime;Check(RegQueryInfoKey(handle,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,out endSubkeys,IntPtr.Zero,IntPtr.Zero,out endValues,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,out endTime));
   if(endTime!=time || endSubkeys!=subkeys || endValues!=values || result.ObjectName!=Name())throw new InvalidOperationException("Registry key changed during bounded observation.");
   return result;
  }
  public static bool Preserved(Observation a,Observation b){return a.ObjectName==b.ObjectName && a.OtherValues==b.OtherValues && a.Children==b.Children && a.Security==b.Security;}
  public Observation Restore(string name,Observation expected,bool exists,int value) {
   if(value<0 || value>1)throw new InvalidOperationException("Unknown recovery value.");
   Observation before=Read(name);
   if(!Preserved(before,expected) || before.LastWrite!=expected.LastWrite || before.Exists!=expected.Exists || (before.Exists && before.Value!=expected.Value))throw new InvalidOperationException("Registry guard changed before value-only recovery.");
   if(exists)Check(RegSetValueEx(handle,name,0,4,BitConverter.GetBytes(value),4));else Check(RegDeleteValue(handle,name));
   Observation after=Read(name);
   if(!Preserved(before,after) || after.Exists!=exists || (exists && after.Value!=value))throw new InvalidOperationException("Registry recovery readback or preservation failed.");
   return after;
  }
  public void Dispose(){if(handle!=IntPtr.Zero){RegCloseKey(handle);handle=IntPtr.Zero;}}
 }
}
