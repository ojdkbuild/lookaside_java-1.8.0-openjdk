/*
 * Copyright (c) 2019, Red Hat, Inc. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

#ifdef REDHAT_ALT_JAVA

#include <sys/prctl.h>


/* Per task speculation control */
#ifndef PR_GET_SPECULATION_CTRL
# define PR_GET_SPECULATION_CTRL    52
#endif
#ifndef PR_SET_SPECULATION_CTRL
# define PR_SET_SPECULATION_CTRL    53
#endif
/* Speculation control variants */
#ifndef PR_SPEC_STORE_BYPASS
# define PR_SPEC_STORE_BYPASS          0
#endif
/* Return and control values for PR_SET/GET_SPECULATION_CTRL */

#ifndef PR_SPEC_NOT_AFFECTED
# define PR_SPEC_NOT_AFFECTED          0
#endif
#ifndef PR_SPEC_PRCTL
# define PR_SPEC_PRCTL                 (1UL << 0)
#endif
#ifndef PR_SPEC_ENABLE
# define PR_SPEC_ENABLE                (1UL << 1)
#endif
#ifndef PR_SPEC_DISABLE
# define PR_SPEC_DISABLE               (1UL << 2)
#endif
#ifndef PR_SPEC_FORCE_DISABLE
# define PR_SPEC_FORCE_DISABLE         (1UL << 3)
#endif
#ifndef PR_SPEC_DISABLE_NOEXEC
# define PR_SPEC_DISABLE_NOEXEC        (1UL << 4)
#endif

static void set_speculation() __attribute__((constructor));
static void set_speculation() {
  if ( prctl(PR_SET_SPECULATION_CTRL,
             PR_SPEC_STORE_BYPASS,
             PR_SPEC_DISABLE_NOEXEC, 0, 0) == 0 ) {
    return;
  }
  prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS, PR_SPEC_DISABLE, 0, 0);
}

#endif // REDHAT_ALT_JAVA
