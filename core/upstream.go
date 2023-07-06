package core

import (
	"fmt"
	"strings"

	"github.com/yaotthaha/cdns/adapter"
)

func sortUpstreams(arr []adapter.Upstream) ([]adapter.Upstream, error) {
	var result []adapter.Upstream
	upstreamMap := make(map[string]adapter.Upstream)
	upstreamTagMap := make(map[adapter.Upstream]string)
	for _, item := range arr {
		tag := item.Tag()
		upstreamMap[tag] = item
		upstreamTagMap[item] = tag
	}
	resultMap := make(map[string]bool)
	for {
		canContinue := false
	startOne:
		for _, item := range arr {
			tag := upstreamTagMap[item]
			if resultMap[tag] {
				continue
			}
			dependencies := item.Dependencies()
			if dependencies != nil && len(dependencies) > 0 {
				for _, dependency := range dependencies {
					if !resultMap[dependency] {
						continue startOne
					}
				}
			}
			resultMap[tag] = true
			canContinue = true
			result = append(result, item)
		}
		if len(resultMap) == len(arr) {
			break
		}
		if canContinue {
			continue
		}
		var currentUpstream adapter.Upstream
		for _, item := range arr {
			if !resultMap[upstreamTagMap[item]] {
				currentUpstream = item
				break
			}
		}
		var lintUpstream func(oTree []string, oCurrent adapter.Upstream) error
		lintUpstream = func(oTree []string, oCurrent adapter.Upstream) error {
			var problemUpstreamTag string
			for _, item := range oCurrent.Dependencies() {
				if !resultMap[item] {
					problemUpstreamTag = item
					break
				}
			}
			for _, item := range oTree {
				if item == problemUpstreamTag {
					return fmt.Errorf("circular upstream dependency: %s -> %s", strings.Join(oTree, " -> "), problemUpstreamTag)
				}
			}
			problemUpstream := upstreamMap[problemUpstreamTag]
			if problemUpstream == nil {
				return fmt.Errorf("upstream dependency [%s] not found for upstream [%s]", problemUpstreamTag, upstreamTagMap[oCurrent])
			}
			return lintUpstream(append(oTree, problemUpstreamTag), problemUpstream)
		}
		return nil, lintUpstream([]string{upstreamTagMap[currentUpstream]}, currentUpstream)
	}
	return result, nil
}
