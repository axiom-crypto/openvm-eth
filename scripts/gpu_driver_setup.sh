#!/bin/bash
#
# Ensures a working NVIDIA driver, switching to the open kernel module flavor
# if needed. Blackwell GPUs require open kernel modules.
set -uo pipefail

if nvidia-smi >/dev/null 2>&1; then
    nvidia-smi
    exit 0
fi

echo "nvidia-smi not functional; switching to open kernel module driver flavor..."
set -ex
sudo apt-get update -qq
sudo apt-get remove -y 'linux-modules-nvidia-580-*' 'nvidia-dkms-580' || true
# Prefer prebuilt modules for the running kernel; fall back to DKMS on version mismatch
sudo apt-get install -y --no-install-recommends nvidia-driver-580-open "linux-modules-nvidia-580-open-$(uname -r)" || \
    sudo apt-get install -y --no-install-recommends nvidia-driver-580-open nvidia-dkms-580-open "linux-headers-$(uname -r)"
sudo rmmod nvidia_uvm nvidia_drm nvidia_modeset nvidia 2>/dev/null || true
sudo modprobe nvidia
sudo modprobe nvidia_uvm
nvidia-smi
