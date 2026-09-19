// Local LSA policy only. No remote target, account deletion or all-rights replacement.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
namespace Wela {
 public static class AuditIntegrityNative {
  [StructLayout(LayoutKind.Sequential)] struct LSA_UNICODE_STRING { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }
  [StructLayout(LayoutKind.Sequential)] struct LSA_OBJECT_ATTRIBUTES { public int Length; public IntPtr RootDirectory; public IntPtr ObjectName; public uint Attributes; public IntPtr SecurityDescriptor; public IntPtr SecurityQualityOfService; }
  [DllImport("advapi32.dll")] static extern uint LsaOpenPolicy(IntPtr system, ref LSA_OBJECT_ATTRIBUTES attributes, uint access, out IntPtr handle);
  [DllImport("advapi32.dll")] static extern uint LsaClose(IntPtr handle);
  [DllImport("advapi32.dll")] static extern uint LsaFreeMemory(IntPtr memory);
  [DllImport("advapi32.dll")] static extern uint LsaNtStatusToWinError(uint status);
  [DllImport("advapi32.dll")] static extern uint LsaEnumerateAccountsWithUserRight(IntPtr handle, ref LSA_UNICODE_STRING right, out IntPtr buffer, out uint count);
  [DllImport("advapi32.dll")] static extern uint LsaEnumerateAccountRights(IntPtr handle, byte[] sid, out IntPtr buffer, out uint count);
  [DllImport("advapi32.dll")] static extern uint LsaAddAccountRights(IntPtr handle, byte[] sid, [In] LSA_UNICODE_STRING[] rights, uint count);
  [DllImport("advapi32.dll")] static extern uint LsaRemoveAccountRights(IntPtr handle, byte[] sid, [MarshalAs(UnmanagedType.U1)] bool allRights, [In] LSA_UNICODE_STRING[] rights, uint count);
  static void Check(uint status) { if (status != 0) throw new Win32Exception((int)LsaNtStatusToWinError(status), "Local LSA operation failed (NTSTATUS 0x" + status.ToString("X8") + ")."); }
  static void CheckRight(string right) { if (right != "SeAuditPrivilege" && right != "SeSecurityPrivilege") throw new ArgumentException("Only the two audit-integrity rights are supported."); }
  static IntPtr Open(bool write) {
   LSA_OBJECT_ATTRIBUTES attributes = new LSA_OBJECT_ATTRIBUTES(); attributes.Length = Marshal.SizeOf(typeof(LSA_OBJECT_ATTRIBUTES));
   IntPtr handle; Check(LsaOpenPolicy(IntPtr.Zero, ref attributes, 0x00000801u | (write ? 0x00000010u : 0u), out handle)); return handle;
  }
  static LSA_UNICODE_STRING Text(string value) {
   LSA_UNICODE_STRING text = new LSA_UNICODE_STRING(); text.Buffer = Marshal.StringToHGlobalUni(value);
   text.Length = checked((ushort)(value.Length * 2)); text.MaximumLength = checked((ushort)(text.Length + 2)); return text;
  }
  static byte[] Sid(string value) { SecurityIdentifier sid = new SecurityIdentifier(value); byte[] bytes = new byte[sid.BinaryLength]; sid.GetBinaryForm(bytes,0); return bytes; }
  public static string[] Holders(string right) {
   CheckRight(right); IntPtr handle = Open(false); IntPtr buffer = IntPtr.Zero; LSA_UNICODE_STRING text = Text(right);
   try {
    uint count; uint status = LsaEnumerateAccountsWithUserRight(handle, ref text, out buffer, out count);
    if (status == 0x8000001Au) return new string[0]; // STATUS_NO_MORE_ENTRIES, documented empty assignment.
    Check(status); List<string> result = new List<string>();
    for (uint i=0; i<count; i++) result.Add(new SecurityIdentifier(Marshal.ReadIntPtr(buffer, checked((int)i * IntPtr.Size))).Value);
    result.Sort(StringComparer.Ordinal); return result.ToArray();
   } finally { try { if (buffer != IntPtr.Zero) Check(LsaFreeMemory(buffer)); } finally { Marshal.FreeHGlobal(text.Buffer); Check(LsaClose(handle)); } }
  }
  public static string[] Rights(string sid) {
   byte[] bytes = Sid(sid); IntPtr handle = Open(false); IntPtr buffer = IntPtr.Zero;
   try {
    uint count; uint status = LsaEnumerateAccountRights(handle, bytes, out buffer, out count);
    if (status == 0xC0000034u) return new string[0]; // STATUS_OBJECT_NAME_NOT_FOUND: no LSA account rights.
    Check(status); int size = Marshal.SizeOf(typeof(LSA_UNICODE_STRING)); List<string> result = new List<string>();
    for (uint i=0; i<count; i++) { LSA_UNICODE_STRING text = (LSA_UNICODE_STRING)Marshal.PtrToStructure(IntPtr.Add(buffer, checked((int)i * size)), typeof(LSA_UNICODE_STRING)); result.Add(Marshal.PtrToStringUni(text.Buffer, text.Length/2)); }
    result.Sort(StringComparer.Ordinal); return result.ToArray();
   } finally { try { if (buffer != IntPtr.Zero) Check(LsaFreeMemory(buffer)); } finally { Check(LsaClose(handle)); } }
  }
  public static void Change(string sid, string right, bool grant) {
   CheckRight(right); byte[] bytes = Sid(sid); IntPtr handle = Open(true); LSA_UNICODE_STRING text = Text(right);
   try {
    LSA_UNICODE_STRING[] rights = new LSA_UNICODE_STRING[] {text};
    // AllRights is always false; only one named privilege is changed.
    Check(grant ? LsaAddAccountRights(handle,bytes,rights,1) : LsaRemoveAccountRights(handle,bytes,false,rights,1));
   } finally { Marshal.FreeHGlobal(text.Buffer); Check(LsaClose(handle)); }
  }
 }
}
