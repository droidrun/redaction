package redaction

import "math"

// log2 is the fdlibm __ieee754_log2 (FreeBSD e_log2.c), the function V8 uses for Math.log2.
// The platform log2 is not used: it can differ in the last bit (SPEC 5.4). Every product that is
// added to something is wrapped in float64(): Go may otherwise fuse it into an FMA on arm64.

const (
	lg1 = 6.666666666666735130e-01
	lg2 = 3.999999999940941908e-01
	lg3 = 2.857142874366239149e-01
	lg4 = 2.222219843214978396e-01
	lg5 = 1.818357216161805012e-01
	lg6 = 1.531383769920937332e-01
	lg7 = 1.479819860511658591e-01

	two54   = 1.80143985094819840000e+16
	ivln2hi = 1.44269504072144627571e+00
	ivln2lo = 1.67517131648865118353e-10
)

func klog1p(f float64) float64 {
	s := f / (2.0 + f)
	z := float64(s * s)
	w := float64(z * z)
	t1 := float64(w * (lg2 + float64(w*(lg4+float64(w*lg6)))))
	t2 := float64(z * (lg1 + float64(w*(lg3+float64(w*(lg5+float64(w*lg7)))))))
	r := t2 + t1
	hfsq := float64(float64(0.5*f) * f)
	return float64(s * (hfsq + r))
}

func highWord(x float64) int32 {
	return int32(math.Float64bits(x) >> 32)
}

func log2fdlibm(x float64) float64 {
	bits := math.Float64bits(x)
	hx := int32(bits >> 32)
	lx := uint32(bits)
	k := int32(0)
	if hx < 0x00100000 {
		if uint32(hx&0x7fffffff)|lx == 0 {
			return math.Inf(-1)
		}
		if hx < 0 {
			return math.NaN()
		}
		k -= 54
		x *= two54
		hx = highWord(x)
	}
	if hx >= 0x7ff00000 {
		return x + x
	}
	if hx == 0x3ff00000 && lx == 0 {
		return 0
	}
	k += (hx >> 20) - 1023
	hx &= 0x000fffff
	i := (hx + 0x95f64) & 0x100000
	low := math.Float64bits(x) & 0xffffffff
	x = math.Float64frombits(uint64(uint32(hx|(i^0x3ff00000)))<<32 | low)
	k += i >> 20
	y := float64(k)
	f := x - 1.0
	hfsq := float64(float64(0.5*f) * f)
	r := klog1p(f)
	hi := f - hfsq
	hi = math.Float64frombits(math.Float64bits(hi) &^ 0xffffffff)
	lo := (f - hi) - hfsq + r
	valHi := float64(hi * ivln2hi)
	valLo := float64(float64(lo+hi)*ivln2lo) + float64(lo*ivln2hi)
	w := y + valHi
	valLo += (y - w) + valHi
	valHi = w
	return valLo + valHi
}
