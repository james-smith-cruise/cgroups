/*
   Copyright The containerd Authors.

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

package cgroups

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStaticPath(t *testing.T) {
	path := StaticPath("test")
	p, err := path("")
	if err != nil {
		t.Fatal(err)
	}
	if p != "test" {
		t.Fatalf("expected static path of \"test\" but received %q", p)
	}
}

func TestSelfPath(t *testing.T) {
	_, err := v1MountPoint()
	if err == ErrMountPointNotExist {
		t.Skip("skipping test that requires cgroup hierarchy")
	} else if err != nil {
		t.Fatal(err)
	}
	paths, err := parseCgroupFile("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	dp := strings.TrimPrefix(paths["devices"], "/")
	path := NestedPath("test")
	p, err := path("devices")
	if err != nil {
		t.Fatal(err)
	}
	if p != filepath.Join("/", dp, "test") {
		t.Fatalf("expected self path of %q but received %q", filepath.Join("/", dp, "test"), p)
	}
}

func TestPidPath(t *testing.T) {
	_, err := v1MountPoint()
	if err == ErrMountPointNotExist {
		t.Skip("skipping test that requires cgroup hierarchy")
	} else if err != nil {
		t.Fatal(err)
	}
	paths, err := parseCgroupFile("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	dp := strings.TrimPrefix(paths["devices"], "/")
	path := PidPath(os.Getpid())
	p, err := path("devices")
	if err != nil {
		t.Fatal(err)
	}
	if p != filepath.Join("/", dp) {
		t.Fatalf("expected self path of %q but received %q", filepath.Join("/", dp), p)
	}
}

func TestRootPath(t *testing.T) {
	p, err := RootPath(Cpu)
	if err != nil {
		t.Error(err)
		return
	}
	if p != "/" {
		t.Errorf("expected / but received %q", p)
	}
}

func TestEmptySubsystem(t *testing.T) {
	const data = `10:devices:/user.slice
	9:net_cls,net_prio:/
	8:blkio:/
	7:freezer:/
	6:perf_event:/
	5:cpuset:/
	4:memory:/
	3:pids:/user.slice/user-1000.slice/user@1000.service
	2:cpu,cpuacct:/
	1:name=systemd:/user.slice/user-1000.slice/user@1000.service/gnome-terminal-server.service
	0::/user.slice/user-1000.slice/user@1000.service/gnome-terminal-server.service`
	r := strings.NewReader(data)
	paths, err := parseCgroupFromReader(r)
	if err != nil {
		t.Fatal(err)
	}
	for subsystem, path := range paths {
		if subsystem == "" {
			t.Fatalf("empty subsystem for %q", path)
		}
	}
}

func TestSystemd240(t *testing.T) {
	if isUnified {
		t.Skipf("requires the system to be running in legacy mode")
	}
	const data = `8:net_cls:/
	7:memory:/system.slice/docker.service
	6:freezer:/
	5:blkio:/system.slice/docker.service
	4:devices:/system.slice/docker.service
	3:cpuset:/
	2:cpu,cpuacct:/system.slice/docker.service
	1:name=systemd:/system.slice/docker.service
	0::/system.slice/docker.service`
	r := strings.NewReader(data)
	paths, err := parseCgroupFromReader(r)
	if err != nil {
		t.Fatal(err)
	}

	path := existingPath(paths, "")
	_, err = path("net_prio")
	if err == nil {
		t.Fatal("error for net_prio shoulld not be nil")
	}
	if err != ErrControllerNotActive {
		t.Fatalf("expected error %q but received %q", ErrControllerNotActive, err)
	}
}

func TestValidUnmountedCgroupHierarchy(t *testing.T) {
	if isUnified {
		t.Skipf("requires the system to be running in legacy mode")
	}
	const data = `9:name=previously-unmounted-hierarchy:/
	8:net_cls:/
	7:memory:/system.slice/docker.service
	6:freezer:/
	5:blkio:/system.slice/docker.service
	4:devices:/system.slice/docker.service
	3:cpuset:/
	2:cpu,cpuacct:/system.slice/docker.service
	1:name=systemd:/system.slice/docker.service
	0::/system.slice/docker.service`
	r := strings.NewReader(data)
	paths, err := parseCgroupFromReader(r)
	if err != nil {
		t.Fatal(err)
	}

	// when a previously unmounted cgroup hierarchy exists in
	// /proc/[pid]/cgroup, existingPath should still succeed, and the returned
	// Path func should still provide useful data.
	path := existingPath(paths, "")
	_, err = path("memory")
	if err != nil {
		t.Fatal(err)
	}

	// This hierarchy should be understood to be inactive.
	_, err = path("name=previously-unmounted-hierarchy")
	if err != ErrControllerNotActive {
		t.Fatalf("expected error %q but received %q", ErrControllerNotActive, err)
	}
}

func TestMountpointNotFound(t *testing.T) {
	if isUnified {
		t.Skipf("requires the system to be running in legacy mode")
	}
	const data = `9:name=unknown-hierarchy:/nonroot.slice/docker.service
	8:net_cls:/
	7:memory:/system.slice/docker.service
	6:freezer:/
	5:blkio:/system.slice/docker.service
	4:devices:/system.slice/docker.service
	3:cpuset:/
	2:cpu,cpuacct:/system.slice/docker.service
	1:name=systemd:/system.slice/docker.service
	0::/system.slice/docker.service`
	r := strings.NewReader(data)
	paths, err := parseCgroupFromReader(r)
	if err != nil {
		t.Fatal(err)
	}

	// If this process is in a non-root cgroup of a hierarchy that cannot
	// be found, this is a real problem.
	path := existingPath(paths, "")
	_, err = path("memory")

	if err != ErrNoCgroupMountDestination {
		t.Fatal("expected error %q, got %q", ErrNoCgroupMountDestination)
	}
}
