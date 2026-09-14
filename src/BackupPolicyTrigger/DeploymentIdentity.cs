using System.Security.Cryptography;

namespace BackupPolicyTrigger;

internal sealed class DeploymentIdentity
{
    public const int ByteLength = 16;

    private readonly byte[] bytes;

    private DeploymentIdentity(byte[] bytes) => this.bytes = bytes;

    public ReadOnlySpan<byte> Bytes => bytes;

    public static DeploymentIdentity CreateRandom() => new(RandomNumberGenerator.GetBytes(ByteLength));

    public static DeploymentIdentity FromBytes(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != ByteLength)
        {
            throw new ArgumentException($"Deployment identity must be exactly {ByteLength} bytes.", nameof(bytes));
        }

        return new(bytes.ToArray());
    }
}
