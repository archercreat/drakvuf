/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2021 Tamas K Lengyel.                                  *
 * Tamas K Lengyel is hereinafter referred to as the author.               *
 * This program is free software; you may redistribute and/or modify it    *
 * under the terms of the GNU General Public License as published by the   *
 * Free Software Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE   *
 * CLARIFICATIONS AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your   *
 * right to use, modify, and redistribute this software under certain      *
 * conditions.  If you wish to embed DRAKVUF technology into proprietary   *
 * software, alternative licenses can be acquired from the author.         *
 *                                                                         *
 * Note that the GPL places important restrictions on "derivative works",  *
 * yet it does not provide a detailed definition of that term.  To avoid   *
 * misunderstandings, we interpret that term as broadly as copyright law   *
 * allows.  For example, we consider an application to constitute a        *
 * derivative work for the purpose of this license if it does any of the   *
 * following with any software or content covered by this license          *
 * ("Covered Software"):                                                   *
 *                                                                         *
 * o Integrates source code from Covered Software.                         *
 *                                                                         *
 * o Reads or includes copyrighted data files.                             *
 *                                                                         *
 * o Is designed specifically to execute Covered Software and parse the    *
 * results (as opposed to typical shell or execution-menu apps, which will *
 * execute anything you tell them to).                                     *
 *                                                                         *
 * o Includes Covered Software in a proprietary executable installer.  The *
 * installers produced by InstallShield are an example of this.  Including *
 * DRAKVUF with other software in compressed or archival form does not     *
 * trigger this provision, provided appropriate open source decompression  *
 * or de-archiving software is widely available for no charge.  For the    *
 * purposes of this license, an installer is considered to include Covered *
 * Software even if it actually retrieves a copy of Covered Software from  *
 * another source during runtime (such as by downloading it from the       *
 * Internet).                                                              *
 *                                                                         *
 * o Links (statically or dynamically) to a library which does any of the  *
 * above.                                                                  *
 *                                                                         *
 * o Executes a helper program, module, or script to do any of the above.  *
 *                                                                         *
 * This list is not exclusive, but is meant to clarify our interpretation  *
 * of derived works with some common examples.  Other people may interpret *
 * the plain GPL differently, so we consider this a special exception to   *
 * the GPL that we apply to Covered Software.  Works which meet any of     *
 * these conditions must conform to all of the terms of this license,      *
 * particularly including the GPL Section 3 requirements of providing      *
 * source code and allowing free redistribution of the work as a whole.    *
 *                                                                         *
 * Any redistribution of Covered Software, including any derived works,    *
 * must obey and carry forward all of the terms of this license, including *
 * obeying all GPL rules and restrictions.  For example, source code of    *
 * the whole work must be provided and free redistribution must be         *
 * allowed.  All GPL references to "this License", are to be treated as    *
 * including the terms and conditions of this license text as well.        *
 *                                                                         *
 * Because this license imposes special exceptions to the GPL, Covered     *
 * Work may not be combined (even as part of a larger work) with plain GPL *
 * software.  The terms, conditions, and exceptions of this license must   *
 * be included as well.  This license is incompatible with some other open *
 * source licenses as well.  In some cases we can relicense portions of    *
 * DRAKVUF or grant special permissions to use it in other open source     *
 * software.  Please contact tamas.k.lengyel@gmail.com with any such       *
 * requests.  Similarly, we don't incorporate incompatible open source     *
 * software into Covered Software without special permission from the      *
 * copyright holders.                                                      *
 *                                                                         *
 * If you have any questions about the licensing restrictions on using     *
 * DRAKVUF in other works, are happy to help.  As mentioned above,         *
 * alternative license can be requested from the author to integrate       *
 * DRAKVUF into proprietary applications and appliances.  Please email     *
 * tamas.k.lengyel@gmail.com for further information.                      *
 *                                                                         *
 * If you have received a written license agreement or contract for        *
 * Covered Software stating terms other than these, you may choose to use  *
 * and redistribute Covered Software under those terms instead of these.   *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes.          *
 *                                                                         *
 * Source code also allows you to port DRAKVUF to new platforms, fix bugs, *
 * and add new features.  You are highly encouraged to submit your changes *
 * on https://github.com/tklengyel/drakvuf, or by other methods.           *
 * By sending these changes, it is understood (unless you specify          *
 * otherwise) that you are offering unlimited, non-exclusive right to      *
 * reuse, modify, and relicense the code.  DRAKVUF will always be          *
 * available Open Source, but this is important because the inability to   *
 * relicense code has caused devastating problems for other Free Software  *
 * projects (such as KDE and NASM).                                        *
 * To specify special license conditions of your contributions, just say   *
 * so when you send them.                                                  *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the DRAKVUF   *
 * license file for more details (it's in a COPYING file included with     *
 * DRAKVUF, and also available from                                        *
 * https://github.com/tklengyel/drakvuf/COPYING)                           *
 *                                                                         *
 ***************************************************************************/
#include <libvmi/libvmi.h>
#include <libdrakvuf/libdrakvuf.h>
#include "plugins/output_format.h"
#include "rootkitmon.h"

#define VISTA_RTM_VER   6000    // Windows Vista SP0
#define W7RTM_VER       7600    // Windows 7 SP0
#define W7SP1_VER       7601    // Windows 7 SP1
#define W8RTM_VER       9200    // Windows 8 SP0
#define W81RTM_VER      9600    // Windows 8.1 RTM

namespace ci
{
struct ci_wrapper
{
    uint8_t ci_enabled;
    sha256_checksum_t ci_callbacks;

    addr_t ci_enabled_va;
    addr_t ci_callbacks_va;

    size_t ci_callbacks_sz;
};

// Global data storage
static ci_wrapper g_data;

static inline size_t get_ci_table_size(vmi_instance_t vmi)
{
    // Table size is heavily dependent on build version but for win 8.1 and
    // higher we just assume table size is 30 elements long
    uint16_t ver = vmi_get_win_buildnumber(vmi);
    if (ver >= VISTA_RTM_VER && ver <= W7SP1_VER)
        return 3;
    else if (ver >= W8RTM_VER)
        return 30;
    return 0;
}

static event_response_t check_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto plugin = GetTrapPlugin<rootkitmon>(info);
    check(drakvuf, info, plugin);
    return VMI_EVENT_RESPONSE_NONE;
}

bool initialize(drakvuf_t drakvuf, rootkitmon* plugin, const rootkitmon_config* config)
{
    vmi_lock_guard vmi(drakvuf);

    if (vmi_get_win_buildnumber(vmi) < W8RTM_VER)
    {
        if (VMI_SUCCESS != vmi_translate_ksym2v(vmi, "g_CiEnabled",   &g_data.ci_enabled_va) ||
            VMI_SUCCESS != vmi_translate_ksym2v(vmi, "g_CiCallbacks", &g_data.ci_callbacks_va))
        {
            PRINT_ROOTKITMON("[ROOTKITMON::CI] Failed to initialize g_CiEnabled or g_CiCallbacks\n");
            return false;
        }
    }
    else
    {
        // On win 8.1 and higher the `g_CiOptions` aka `g_CiEnabled` is located in ci.dll module
        if (!config->ci_profile)
            return false;

        // Extract g_CiOptions rva from json file
        auto profile_json = json_object_from_file(config->ci_profile);
        if (!profile_json)
        {
            PRINT_ROOTKITMON("[ROOTKITMON::CI] Failed to load JSON debug info for ci.dll\n");
            return false;
        }

        addr_t ci_options_rva;
        if (!json_get_symbol_rva(drakvuf, profile_json, "g_CiOptions", &ci_options_rva))
        {
            PRINT_ROOTKITMON("[ROOTKITMON::CI] Failed to find g_CiOptions RVA in json for ci.dll\n");
            return false;
        }
        json_object_put(profile_json);

        addr_t list_head;
        if (VMI_SUCCESS != vmi_read_addr_ksym(vmi, "PsLoadedModuleList", &list_head))
        {
            PRINT_ROOTKITMON("[ROOTKITMON::CI] Failed to read PsLoadedModuleList\n");
            return false;
        }

        addr_t ci_module_base;
        if (!drakvuf_get_module_base_addr(drakvuf, list_head, "ci.dll", &ci_module_base))
        {
            PRINT_ROOTKITMON("[ROOTKITMON::CI] Failed to get ci.dll\n");
            return false;
        }

        g_data.ci_enabled_va = ci_module_base + ci_options_rva;

        if (VMI_SUCCESS != vmi_translate_ksym2v(vmi, "SeCiCallbacks", &g_data.ci_callbacks_va))
        {
            PRINT_ROOTKITMON("[ROOTKITMON::CI] Failed to find SeCiCallbacks\n");
            return false;
        }
    }

    // Fill initial values
    vmi_read_8_va(vmi, g_data.ci_enabled_va, 4, &g_data.ci_enabled);
    g_data.ci_callbacks_sz = get_ci_table_size(vmi);
    g_data.ci_callbacks = calc_checksum(vmi, g_data.ci_callbacks_va, g_data.ci_callbacks_sz);

    plugin->syscall_hooks.push_back(plugin->createSyscallHook("SeValidateImageHeader", check_cb));
    plugin->syscall_hooks.push_back(plugin->createSyscallHook("SeValidateImageData", check_cb));

    return true;
}

void check(drakvuf_t drakvuf, drakvuf_trap_info_t* info, rootkitmon* plugin)
{
    vmi_lock_guard vmi(drakvuf);

    uint8_t ci_enabled;
    if (VMI_SUCCESS != vmi_read_8_va(vmi, g_data.ci_enabled_va, 4, &ci_enabled))
    {
        PRINT_ROOTKITMON("[ROOTKITMON::CI] Failed to read g_CiEnabled\n");
        throw -1;
    }

    auto ci_callbacks = calc_checksum(vmi, g_data.ci_callbacks_va, g_data.ci_callbacks_sz);

    if (g_data.ci_enabled != ci_enabled)
    {
        fmt::print(plugin->format, "rootkitmon", drakvuf, info,
            keyval("Reason", fmt::Qstr("g_CiEnabled modification")));
    }

    if (g_data.ci_callbacks != ci_callbacks)
    {
        fmt::print(plugin->format, "rootkitmon", drakvuf, info,
            keyval("Reason", fmt::Qstr("g_CiCallbacks modification")));
    }
}
}