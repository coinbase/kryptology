package bls12381

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFp12Arithmetic(t *testing.T) {
	var aa, bb, cc, d, e, f fp12
	a := fp12{
		A: fp6{
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
		},
		B: fp6{
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
		},
	}

	b := fp12{
		A: fp6{
			A: fp2{
				A: fp{
					0x47f9_cb98_b1b8_2d58,
					0x5fe9_11eb_a3aa_1d9d,
					0x96bf_1b5f_4dd8_1db3,
					0x8100_d272_c925_9f5b,
					0xafa2_0b96_7464_0eab,
					0x09bb_cea7_d8d9_497d,
				},
				B: fp{
					0x0303_cb98_b166_2daa,
					0xd931_10aa_0a62_1d5a,
					0xbfa9_820c_5be4_a468,
					0x0ba3_643e_cb05_a348,
					0xdc35_34bb_1f1c_25a6,
					0x06c3_05bb_19c0_e1c1,
				},
			},
			B: fp2{
				A: fp{
					0x46f9_cb98_b162_d858,
					0x0be9_109c_f7aa_1d57,
					0xc791_bc55_fece_41d2,
					0xf84c_5770_4e38_5ec2,
					0xcb49_c1d9_c010_e60f,
					0x0acd_b8e1_58bf_e348,
				},
				B: fp{
					0x8aef_cb98_b15f_8306,
					0x3ea1_108f_e4f2_1d54,
					0xcf79_f69f_a1b7_df3b,
					0xe4f5_4aa1_d16b_1a3c,
					0xba5e_4ef8_6105_a679,
					0x0ed8_6c07_97be_e5cf,
				},
			},
			C: fp2{
				A: fp{
					0xcee5_cb98_b15c_2db4,
					0x7159_1082_d23a_1d51,
					0xd762_30e9_44a1_7ca4,
					0xd19e_3dd3_549d_d5b6,
					0xa972_dc17_01fa_66e3,
					0x12e3_1f2d_d6bd_e7d6,
				},
				B: fp{
					0xad2a_cb98_b173_2d9d,
					0x2cfd_10dd_0696_1d64,
					0x0739_6b86_c6ef_24e8,
					0xbd76_e2fd_b1bf_c820,
					0x6afe_a7f6_de94_d0d5,
					0x1099_4b0c_5744_c040,
				},
			},
		},
		B: fp6{
			A: fp2{
				A: fp{
					0x47f9_cb98_b1b8_2d58,
					0x5fe9_11eb_a3aa_1d9d,
					0x96bf_1b5f_4dd2_1db3,
					0x8100_d27c_c925_9f5b,
					0xafa2_0b96_7464_0eab,
					0x09bb_cea7_d8d9_497d,
				},
				B: fp{
					0x0303_cb98_b166_2daa,
					0xd931_10aa_0a62_1d5a,
					0xbfa9_820c_5be4_a468,
					0x0ba3_643e_cb05_a348,
					0xdc35_34bb_1f1c_25a6,
					0x06c3_05bb_19c0_e1c1,
				},
			},
			B: fp2{
				A: fp{
					0x46f9_cb98_b162_d858,
					0x0be9_109c_f7aa_1d57,
					0xc791_bc55_fece_41d2,
					0xf84c_5770_4e38_5ec2,
					0xcb49_c1d9_c010_e60f,
					0x0acd_b8e1_58bf_e3c8,
				},
				B: fp{
					0x8aef_cb98_b15f_8306,
					0x3ea1_108f_e4f2_1d54,
					0xcf79_f69f_a117_df3b,
					0xe4f5_4aa1_d16b_1a3c,
					0xba5e_4ef8_6105_a679,
					0x0ed8_6c07_97be_e5cf,
				},
			},
			C: fp2{
				A: fp{
					0xcee5_cb98_b15c_2db4,
					0x7159_1082_d23a_1d51,
					0xd762_30e9_44a1_7ca4,
					0xd19e_3dd3_549d_d5b6,
					0xa972_dc17_01fa_66e3,
					0x12e3_1f2d_d6bd_e7d6,
				},
				B: fp{
					0xad2a_cb98_b173_2d9d,
					0x2cfd_10dd_0696_1d64,
					0x0739_6b86_c6ef_24e8,
					0xbd76_e2fd_b1bf_c820,
					0x6afe_a7f6_de94_d0d5,
					0x1099_4b0c_5744_c040,
				},
			},
		},
	}

	c := fp12{
		A: fp6{
			A: fp2{
				A: fp{
					0x47f9_cb98_71b8_2d58,
					0x5fe9_11eb_a3aa_1d9d,
					0x96bf_1b5f_4dd8_1db3,
					0x8100_d27c_c925_9f5b,
					0xafa2_0b96_7464_0eab,
					0x09bb_cea7_d8d9_497d,
				},
				B: fp{
					0x0303_cb98_b166_2daa,
					0xd931_10aa_0a62_1d5a,
					0xbfa9_820c_5be4_a468,
					0x0ba3_643e_cb05_a348,
					0xdc35_34bb_1f1c_25a6,
					0x06c3_05bb_19c0_e1c1,
				},
			},
			B: fp2{
				A: fp{
					0x46f9_cb98_b162_d858,
					0x0be9_109c_f7aa_1d57,
					0x7791_bc55_fece_41d2,
					0xf84c_5770_4e38_5ec2,
					0xcb49_c1d9_c010_e60f,
					0x0acd_b8e1_58bf_e3c8,
				},
				B: fp{
					0x8aef_cb98_b15f_8306,
					0x3ea1_108f_e4f2_1d54,
					0xcf79_f69f_a1b7_df3b,
					0xe4f5_4aa1_d16b_133c,
					0xba5e_4ef8_6105_a679,
					0x0ed8_6c07_97be_e5cf,
				},
			},
			C: fp2{
				A: fp{
					0xcee5_cb98_b15c_2db4,
					0x7159_1082_d23a_1d51,
					0xd762_40e9_44a1_7ca4,
					0xd19e_3dd3_549d_d5b6,
					0xa972_dc17_01fa_66e3,
					0x12e3_1f2d_d6bd_e7d6,
				},
				B: fp{
					0xad2a_cb98_b173_2d9d,
					0x2cfd_10dd_0696_1d64,
					0x0739_6b86_c6ef_24e8,
					0xbd76_e2fd_b1bf_c820,
					0x6afe_a7f6_de94_d0d5,
					0x1099_4b0c_1744_c040,
				},
			},
		},
		B: fp6{
			A: fp2{
				A: fp{
					0x47f9_cb98_b1b8_2d58,
					0x5fe9_11eb_a3aa_1d9d,
					0x96bf_1b5f_4dd8_1db3,
					0x8100_d27c_c925_9f5b,
					0xafa2_0b96_7464_0eab,
					0x09bb_cea7_d8d9_497d,
				},
				B: fp{
					0x0303_cb98_b166_2daa,
					0xd931_10aa_0a62_1d5a,
					0xbfa9_820c_5be4_a468,
					0x0ba3_643e_cb05_a348,
					0xdc35_34bb_1f1c_25a6,
					0x06c3_05bb_19c0_e1c1,
				},
			},
			B: fp2{
				A: fp{
					0x46f9_cb98_b162_d858,
					0x0be9_109c_f7aa_1d57,
					0xc791_bc55_fece_41d2,
					0xf84c_5770_4e38_5ec2,
					0xcb49_c1d3_c010_e60f,
					0x0acd_b8e1_58bf_e3c8,
				},
				B: fp{
					0x8aef_cb98_b15f_8306,
					0x3ea1_108f_e4f2_1d54,
					0xcf79_f69f_a1b7_df3b,
					0xe4f5_4aa1_d16b_1a3c,
					0xba5e_4ef8_6105_a679,
					0x0ed8_6c07_97be_e5cf,
				},
			},
			C: fp2{
				A: fp{
					0xcee5_cb98_b15c_2db4,
					0x7159_1082_d23a_1d51,
					0xd762_30e9_44a1_7ca4,
					0xd19e_3dd3_549d_d5b6,
					0xa972_dc17_01fa_66e3,
					0x12e3_1f2d_d6bd_e7d6,
				},
				B: fp{
					0xad2a_cb98_b173_2d9d,
					0x2cfd_10dd_0696_1d64,
					0x0739_6b86_c6ef_24e8,
					0xbd76_e2fd_b1bf_c820,
					0x6afe_a7f6_de94_d0d5,
					0x1099_4b0c_5744_1040,
				},
			},
		},
	}

	aa.Square(&a)
	aa.Invert(&aa)
	aa.Square(&aa)
	aa.Add(&aa, &c)

	bb.Square(&b)
	bb.Invert(&bb)
	bb.Square(&bb)
	bb.Add(&bb, &aa)

	cc.Square(&c)
	cc.Invert(&cc)
	cc.Square(&cc)
	cc.Add(&cc, &bb)

	d.Square(&aa)
	e.Mul(&aa, &aa)
	require.Equal(t, 1, e.Equal(&d))

	d.Square(&bb)
	e.Mul(&bb, &bb)
	require.Equal(t, 1, e.Equal(&d))

	d.Square(&cc)
	e.Mul(&cc, &cc)
	require.Equal(t, 1, e.Equal(&d))

	d.Square(&cc)
	e.Add(&aa, &bb)
	d.Mul(&d, &e)

	e.Mul(&cc, &cc)
	e.Mul(&e, &aa)
	f.Mul(&cc, &cc)
	f.Mul(&f, &bb)
	e.Add(&e, &f)

	require.Equal(t, 1, e.Equal(&d))

	d.Invert(&aa)
	e.Invert(&bb)
	f.Mul(&aa, &bb)
	f.Invert(&f)
	require.Equal(t, 1, f.Equal(e.Mul(&e, &d)))

	require.Equal(t, 1, d.Mul(&d, &aa).IsOne())

	require.Equal(t, 0, aa.Equal(d.FrobeniusMap(&aa)))
	d.FrobeniusMap(&aa).
		FrobeniusMap(&d).
		FrobeniusMap(&d).
		FrobeniusMap(&d).
		FrobeniusMap(&d).
		FrobeniusMap(&d).
		FrobeniusMap(&d).
		FrobeniusMap(&d).
		FrobeniusMap(&d).
		FrobeniusMap(&d).
		FrobeniusMap(&d).
		FrobeniusMap(&d)
	require.Equal(t, 1, aa.Equal(&d))
}
