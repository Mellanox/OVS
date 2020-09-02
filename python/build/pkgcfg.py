# Copyright (c) 2020 Intel, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License")
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# Distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# Limitations under the License.

# The purpose of this script is to parse the libraries
# From pkg-config in case of DPDK Meson builds.

import sys
def parse_pkg_cfg_libs(arg):
    linker_prefix = "-Wl,"
    # Libtool expects libraries to be comma separated
    # And -Wl must appear only once.
    final_string = ','.join(map(str.strip,arg[1:])).replace('-Wl,','')
    final_string = arg[0]+" "+linker_prefix+final_string
    # Ld only understands -lpthread.
    final_string = final_string.replace('-pthread','-lpthread')
    return final_string

if __name__ == "__main__":
    print(parse_pkg_cfg_libs(sys.argv[1:]))
