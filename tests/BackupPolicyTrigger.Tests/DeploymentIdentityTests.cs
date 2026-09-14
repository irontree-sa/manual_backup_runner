using BackupPolicyTrigger;

namespace BackupPolicyTrigger.Tests;

public sealed class DeploymentIdentityTests
{
    [Fact]
    public void FromBytes_requires_exactly_128_bits_and_copies_the_input()
    {
        var source = Enumerable.Range(0, DeploymentIdentity.ByteLength).Select(i => (byte)i).ToArray();

        var identity = DeploymentIdentity.FromBytes(source);
        source[0] = 255;

        Assert.True(identity.Bytes.SequenceEqual(Enumerable.Range(0, DeploymentIdentity.ByteLength).Select(i => (byte)i).ToArray()));
        Assert.Throws<ArgumentException>(() => DeploymentIdentity.FromBytes(new byte[DeploymentIdentity.ByteLength - 1]));
        Assert.Throws<ArgumentException>(() => DeploymentIdentity.FromBytes(new byte[DeploymentIdentity.ByteLength + 1]));
    }

    [Fact]
    public void CreateRandom_produces_distinct_128_bit_identities()
    {
        var first = DeploymentIdentity.CreateRandom();
        var second = DeploymentIdentity.CreateRandom();

        Assert.Equal(DeploymentIdentity.ByteLength, first.Bytes.Length);
        Assert.Equal(DeploymentIdentity.ByteLength, second.Bytes.Length);
        Assert.False(first.Bytes.SequenceEqual(second.Bytes));
    }
}
