package convert

import (
	"fmt"

	"github.com/xmdhs/clash2singbox/model/singbox"
)

func relay(slm map[string]singbox.SingBoxOut, pl []string, name string) []singbox.SingBoxOut {
	plLen := len(pl)
	if plLen < 2 {
		return nil
	}
	sl := make([]singbox.SingBoxOut, 0, plLen)
	s0 := slm[pl[plLen-1]]
	for i := plLen - 2; i >= 0; i-- {
		s1, ok := slm[pl[i]]
		if !ok {
			return nil
		}
		s1.Detour = s0.Tag
		if i != 0 {
			s1.Ignored = true
		}
		s1.Tag = fmt.Sprintf("%v-%v-%v", s1.Tag, "relay", name)
		s0 = s1
		sl = append(sl, s1)
	}
	return sl
}
