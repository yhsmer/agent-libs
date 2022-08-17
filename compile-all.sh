set -e
set -x
cd /root/code/cc/agent-libs/build
# cmake -DBUILD_LIBSCAP_EXAMPLES=OFF -DMINIMAL_BUILD=ON -DCREATE_TEST_TARGETS=OFF -DBUILD_LIBSINSP_EXAMPLES=ON ..
make
cd /root/code/cc/agent-libs/driver/bpf
make
export SYSDIG_BPF_PROBE=/root/code/cc/agent-libs/driver/bpf/probe.o
cd /root/code/cc/agent-libs/build/libsinsp/examples/
./sinsp-example
