package bls12381

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFp6Arithmetic(t *testing.T) {
	a := fp6{
		A: fp2{
			A: fp{
				0x47f9cb98b1b82d58,
				0x5fe911eba3aa1d9d,
				0x96bf1b5f4dd81db3,
				0x8100d27cc9259f5b,
				0xafa20b9674640eab,
				0x09bbcea7d8d9497d,
			},
			B: fp{
				0x0303cb98b1662daa,
				0xd93110aa0a621d5a,
				0xbfa9820c5be4a468,
				0x0ba3643ecb05a348,
				0xdc3534bb1f1c25a6,
				0x06c305bb19c0e1c1,
			},
		},
		B: fp2{
			A: fp{
				0x46f9cb98b162d858,
				0x0be9109cf7aa1d57,
				0xc791bc55fece41d2,
				0xf84c57704e385ec2,
				0xcb49c1d9c010e60f,
				0x0acdb8e158bfe3c8,
			},
			B: fp{
				0x8aefcb98b15f8306,
				0x3ea1108fe4f21d54,
				0xcf79f69fa1b7df3b,
				0xe4f54aa1d16b1a3c,
				0xba5e4ef86105a679,
				0x0ed86c0797bee5cf,
			},
		},
		C: fp2{
			A: fp{
				0xcee5cb98b15c2db4,
				0x71591082d23a1d51,
				0xd76230e944a17ca4,
				0xd19e3dd3549dd5b6,
				0xa972dc1701fa66e3,
				0x12e31f2dd6bde7d6,
			},
			B: fp{
				0xad2acb98b1732d9d,
				0x2cfd10dd06961d64,
				0x07396b86c6ef24e8,
				0xbd76e2fdb1bfc820,
				0x6afea7f6de94d0d5,
				0x10994b0c5744c040,
			},
		},
	}
	b := fp6{
		A: fp2{
			A: fp{
				0xf120cb98b16fd84b,
				0x5fb510cff3de1d61,
				0x0f21a5d069d8c251,
				0xaa1fd62f34f2839a,
				0x5a1335157f89913f,
				0x14a3fe329643c247,
			},
			B: fp{
				0x3516cb98b16c82f9,
				0x926d10c2e1261d5f,
				0x1709e01a0cc25fba,
				0x96c8c960b8253f14,
				0x4927c234207e51a9,
				0x18aeb158d542c44e,
			},
		},
		B: fp2{
			A: fp{
				0xbf0dcb98b16982fc,
				0xa67910b71d1a1d5c,
				0xb7c147c2b8fb06ff,
				0x1efa710d47d2e7ce,
				0xed20a79c7e27653c,
				0x02b85294dac1dfba,
			},
			B: fp{
				0x9d52cb98b18082e5,
				0x621d111151761d6f,
				0xe79882603b48af43,
				0x0ad31637a4f4da37,
				0xaeac737c5ac1cf2e,
				0x006e7e735b48b824,
			},
		},
		C: fp2{
			A: fp{
				0xe148cb98b17d2d93,
				0x94d511043ebe1d6c,
				0xef80bca9de324cac,
				0xf77c0969282795b1,
				0x9dc1009afbb68f97,
				0x047931999a47ba2b,
			},
			B: fp{
				0x253ecb98b179d841,
				0xc78d10f72c061d6a,
				0xf768f6f3811bea15,
				0xe424fc9aab5a512b,
				0x8cd58db99cab5001,
				0x0883e4bfd946bc32,
			},
		},
	}
	c := fp6{
		A: fp2{
			A: fp{
				0x6934cb98b17682ef,
				0xfa4510ea194e1d67,
				0xff51313d2405877e,
				0xd0cdefcc2e8d0ca5,
				0x7bea1ad83da0106b,
				0x0c8e97e61845be39,
			},
			B: fp{
				0x4779cb98b18d82d8,
				0xb5e911444daa1d7a,
				0x2f286bdaa6532fc2,
				0xbca694f68baeff0f,
				0x3d75e6b81a3a7a5d,
				0x0a44c3c498cc96a3,
			},
		},
		B: fp2{
			A: fp{
				0x8b6fcb98b18a2d86,
				0xe8a111373af21d77,
				0x3710a624493ccd2b,
				0xa94f88280ee1ba89,
				0x2c8a73d6bb2f3ac7,
				0x0e4f76ead7cb98aa,
			},
			B: fp{
				0xcf65cb98b186d834,
				0x1b59112a283a1d74,
				0x3ef8e06dec266a95,
				0x95f87b5992147603,
				0x1b9f00f55c23fb31,
				0x125a2a1116ca9ab1,
			},
		},
		C: fp2{
			A: fp{
				0x135bcb98b18382e2,
				0x4e11111d15821d72,
				0x46e11ab78f1007fe,
				0x82a16e8b1547317d,
				0x0ab38e13fd18bb9b,
				0x1664dd3755c99cb8,
			},
			B: fp{
				0xce65cb98b1318334,
				0xc7590fdb7c3a1d2e,
				0x6fcb81649d1c8eb3,
				0x0d44004d1727356a,
				0x3746b738a7d0d296,
				0x136c144a96b134fc,
			},
		},
	}

	d := new(fp6).Square(&a)
	e := new(fp6).Mul(&a, &a)
	require.Equal(t, 1, e.Equal(d))

	d.Square(&b)
	e.Mul(&b, &b)
	require.Equal(t, 1, e.Equal(d))

	d.Square(&c)
	e.Mul(&c, &c)
	require.Equal(t, 1, e.Equal(d))

	// (a + b) * c^2
	d.Add(&a, &b)
	d.Mul(d, new(fp6).Square(&c))

	e.Mul(&c, &c)
	e.Mul(e, &a)
	tt := new(fp6).Mul(&c, &c)
	tt.Mul(tt, &b)
	e.Add(e, tt)

	require.Equal(t, 1, d.Equal(e))

	_, wasInverted := d.Invert(&a)
	require.Equal(t, 1, wasInverted)
	_, wasInverted = e.Invert(&b)
	require.Equal(t, 1, wasInverted)

	tt.Mul(&a, &b)
	_, wasInverted = tt.Invert(tt)
	require.Equal(t, 1, wasInverted)
	d.Mul(d, e)
	require.Equal(t, 1, tt.Equal(d))

	_, _ = d.Invert(&a)
	e.SetOne()
	require.Equal(t, 1, e.Equal(d.Mul(d, &a)))
}
