// Fixed offline chain build. No certificate/key store or policy writes.
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
namespace Wela.Capi2Probe {
 public sealed class ChainResult { public uint Flags, ErrorStatus, InfoStatus, Chains, Elements; }
 public static class Native {
  public const uint OfflineFlags=0x80002104; // cache-only URL/revocation, no AIA, no auth-root auto-update
  [StructLayout(LayoutKind.Sequential)] struct Usage { public uint Count; public IntPtr Oids; }
  [StructLayout(LayoutKind.Sequential)] struct Match { public uint Type; public Usage Usage; }
  [StructLayout(LayoutKind.Sequential)] struct Parameters {
   public uint Size; public Match RequestedUsage,RequestedIssuancePolicy;
   public uint UrlTimeout; public int CheckFreshness; public uint Freshness;
   public IntPtr CacheResync,StrongSign; public uint StrongFlags;
  }
  // Both CERT_CHAIN_CONTEXT and CERT_SIMPLE_CHAIN have this documented prefix.
  [StructLayout(LayoutKind.Sequential)] struct ChainPrefix { public uint Size,Error,Info,Count; public IntPtr Entries; }
  [DllImport("crypt32.dll",ExactSpelling=true,SetLastError=true)] static extern IntPtr CertCreateCertificateContext(uint encoding,byte[] encoded,uint length);
  [DllImport("crypt32.dll",ExactSpelling=true,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool CertGetCertificateChain(IntPtr engine,IntPtr certificate,IntPtr time,IntPtr additionalStore,ref Parameters parameters,uint flags,IntPtr reserved,out IntPtr chain);
  [DllImport("crypt32.dll",ExactSpelling=true)] static extern void CertFreeCertificateChain(IntPtr chain);
  [DllImport("crypt32.dll",ExactSpelling=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool CertFreeCertificateContext(IntPtr certificate);
  public static ChainResult Build(byte[] der) {
   if(IntPtr.Size!=8 || Marshal.SizeOf(typeof(Parameters))!=96 || Marshal.SizeOf(typeof(ChainPrefix))!=24)throw new InvalidOperationException("Unsupported native chain structure layout.");
   if(der==null || der.Length<128 || der.Length>8192)throw new ArgumentException("Certificate DER exceeds the fixed bound.");
   IntPtr certificate=CertCreateCertificateContext(1,der,(uint)der.Length),chain=IntPtr.Zero;
   if(certificate==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());
   try {
    Parameters p=new Parameters();p.Size=(uint)Marshal.SizeOf(typeof(Parameters));p.UrlTimeout=1000;
    // No revocation-check request, additional store, custom trust engine, or caching of the end certificate.
    if(!CertGetCertificateChain(IntPtr.Zero,certificate,IntPtr.Zero,IntPtr.Zero,ref p,OfflineFlags,IntPtr.Zero,out chain))throw new Win32Exception(Marshal.GetLastWin32Error());
    if(chain==IntPtr.Zero)throw new InvalidOperationException("Native chain context is absent.");
    ChainPrefix c=(ChainPrefix)Marshal.PtrToStructure(chain,typeof(ChainPrefix));
    if(c.Size<24 || c.Count!=1 || c.Entries==IntPtr.Zero)throw new InvalidOperationException("Unexpected native chain shape.");
    IntPtr simple=Marshal.ReadIntPtr(c.Entries);if(simple==IntPtr.Zero)throw new InvalidOperationException("Native simple chain is absent.");
    ChainPrefix s=(ChainPrefix)Marshal.PtrToStructure(simple,typeof(ChainPrefix));
    if(s.Size<24 || s.Count!=1 || s.Entries==IntPtr.Zero || s.Error!=c.Error)throw new InvalidOperationException("Unexpected native simple chain shape.");
    return new ChainResult {Flags=OfflineFlags,ErrorStatus=c.Error,InfoStatus=c.Info,Chains=c.Count,Elements=s.Count};
   } finally {if(chain!=IntPtr.Zero)CertFreeCertificateChain(chain);CertFreeCertificateContext(certificate);}
  }
 }
}
