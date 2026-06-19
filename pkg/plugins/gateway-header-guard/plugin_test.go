/*
Copyright 2026 The opendatahub.io Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package gateway_header_guard

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/llm-d/llm-d-inference-payload-processor/pkg/framework/interface/plugin"
	"github.com/llm-d/llm-d-inference-payload-processor/pkg/framework/interface/requesthandling"
)

func TestFactory(t *testing.T) {
	p, err := Factory("test", nil, nil)
	require.NoError(t, err)
	assert.Equal(t, "test", p.TypedName().Name)
	assert.Equal(t, PluginType, p.TypedName().Type)
}

func TestProcessRequest_StripsInternalHeaders(t *testing.T) {
	p, _ := Factory("test", nil, nil)
	cs := plugin.NewCycleState()
	req := requesthandling.NewInferenceRequest()
	req.Headers["x-maas-username"] = "alice"
	req.Headers["x-maas-group"] = "engineering"
	req.Headers["x-maas-subscription"] = "premium"
	req.Headers["content-type"] = "application/json"
	req.Headers["authorization"] = "Bearer sk-oai-test"

	err := p.(*Plugin).ProcessRequest(context.Background(), cs, req)
	require.NoError(t, err)

	// Internal headers stripped
	_, hasUser := req.Headers["x-maas-username"]
	assert.False(t, hasUser, "x-maas-username must be stripped")
	_, hasGroup := req.Headers["x-maas-group"]
	assert.False(t, hasGroup, "x-maas-group must be stripped")
	_, hasSub := req.Headers["x-maas-subscription"]
	assert.False(t, hasSub, "x-maas-subscription must be stripped")

	// Non-internal headers preserved
	assert.Equal(t, "application/json", req.Headers["content-type"])
	assert.Equal(t, "Bearer sk-oai-test", req.Headers["authorization"])

	// Values saved in CycleState
	username, err := plugin.ReadCycleStateKey[string](cs, "x-maas-username")
	require.NoError(t, err)
	assert.Equal(t, "alice", username)

	group, err := plugin.ReadCycleStateKey[string](cs, "x-maas-group")
	require.NoError(t, err)
	assert.Equal(t, "engineering", group)

	sub, err := plugin.ReadCycleStateKey[string](cs, "x-maas-subscription")
	require.NoError(t, err)
	assert.Equal(t, "premium", sub)
}

func TestProcessRequest_NoInternalHeaders(t *testing.T) {
	p, _ := Factory("test", nil, nil)
	cs := plugin.NewCycleState()
	req := requesthandling.NewInferenceRequest()
	req.Headers["content-type"] = "application/json"

	err := p.(*Plugin).ProcessRequest(context.Background(), cs, req)
	require.NoError(t, err)

	assert.Equal(t, "application/json", req.Headers["content-type"])
}

func TestProcessRequest_CaseInsensitive(t *testing.T) {
	p, _ := Factory("test", nil, nil)
	cs := plugin.NewCycleState()
	req := requesthandling.NewInferenceRequest()
	req.Headers["X-MaaS-Username"] = "bob"

	err := p.(*Plugin).ProcessRequest(context.Background(), cs, req)
	require.NoError(t, err)

	_, hasHeader := req.Headers["X-MaaS-Username"]
	assert.False(t, hasHeader, "mixed-case x-maas header must be stripped")

	val, err := plugin.ReadCycleStateKey[string](cs, "X-MaaS-Username")
	require.NoError(t, err)
	assert.Equal(t, "bob", val)
}
