#!/bin/bash
#
# Copyright (c) 2013-2021 Igor Pecovnik, igor.pecovnik@gma**.com
#
# This file is licensed under the terms of the GNU General Public
# License version 2. This program is licensed "as is" without any
# warranty of any kind, whether express or implied.
#
# This file is a part of the Armbian build script
# https://github.com/armbian/build/

# Functions:

# compilation_prepare




compilation_prepare()
{

	# Packaging patch for modern kernels should be one for all.
	# Currently we have it per kernel family since we can't have one
	# Maintaining one from central location starting with 5.3+
	# Temporally set for new "default->legacy,next->current" family naming

	if linux-version compare "${version}" ge 5.10; then

		if test -d ${kerneldir}/debian
		then
			rm -rf ${kerneldir}/debian/*
		fi
		sed -i -e '
			s/^KBUILD_IMAGE	:= \$(boot)\/Image\.gz$/KBUILD_IMAGE	:= \$(boot)\/Image/
		' ${kerneldir}/arch/arm64/Makefile

		rm -f ${kerneldir}/scripts/package/{builddeb,mkdebian}

		cp ${SRC}/packages/armbian/builddeb ${kerneldir}/scripts/package/builddeb
		cp ${SRC}/packages/armbian/mkdebian ${kerneldir}/scripts/package/mkdebian

		chmod 755 ${kerneldir}/scripts/package/{builddeb,mkdebian}

	elif linux-version compare "${version}" ge 5.8.17 \
		&& linux-version compare "${version}" le 5.9 \
		|| linux-version compare "${version}" ge 5.9.2; then
			display_alert "Adjusting" "packaging" "info"
			cd "$kerneldir" || exit
			process_patch_file "${SRC}/patch/misc/general-packaging-5.8-9.y.patch" "applying"
	elif linux-version compare "${version}" ge 5.6; then
		display_alert "Adjusting" "packaging" "info"
		cd "$kerneldir" || exit
		process_patch_file "${SRC}/patch/misc/general-packaging-5.6.y.patch" "applying"
	elif linux-version compare "${version}" ge 5.3; then
		display_alert "Adjusting" "packaging" "info"
		cd "$kerneldir" || exit
		process_patch_file "${SRC}/patch/misc/general-packaging-5.3.y.patch" "applying"
	fi

	if [[ "${version}" == "4.19."* ]] && [[ "$LINUXFAMILY" == sunxi* || "$LINUXFAMILY" == meson64 || \
	"$LINUXFAMILY" == mvebu64 || "$LINUXFAMILY" == mt7623 || "$LINUXFAMILY" == mvebu ]]; then
		display_alert "Adjusting" "packaging" "info"
		cd "$kerneldir" || exit
		process_patch_file "${SRC}/patch/misc/general-packaging-4.19.y.patch" "applying"
	fi

        if [[ "${version}" == "4.19."* ]] && [[ "$LINUXFAMILY" == rk35xx ]]; then
                display_alert "Adjusting" "packaging" "info"
                cd "$kerneldir" || exit
                process_patch_file "${SRC}/patch/misc/general-packaging-4.19.y-rk35xx.patch" "applying"
        fi

	if [[ "${version}" == "4.14."* ]] && [[ "$LINUXFAMILY" == s5p6818 || "$LINUXFAMILY" == mvebu64 || \
	"$LINUXFAMILY" == imx7d || "$LINUXFAMILY" == odroidxu4 || "$LINUXFAMILY" == mvebu ]]; then
		display_alert "Adjusting" "packaging" "info"
		cd "$kerneldir" || exit
		process_patch_file "${SRC}/patch/misc/general-packaging-4.14.y.patch" "applying"
	fi

	if [[ "${version}" == "4.4."* || "${version}" == "4.9."* ]] && \
	[[ "$LINUXFAMILY" == rockpis || "$LINUXFAMILY" == rk3399 ]]; then
		display_alert "Adjusting" "packaging" "info"
		cd "$kerneldir" || exit
		process_patch_file "${SRC}/patch/misc/general-packaging-4.4.y-rk3399.patch" "applying"
	fi

	if [[ "${version}" == "4.4."* ]] && \
	[[ "$LINUXFAMILY" == rockchip64 || "$LINUXFAMILY" == media* ]]; then
		display_alert "Adjusting" "packaging" "info"
		cd "$kerneldir" || exit
		if [[ $BOARD == nanopct4 ]]; then
			process_patch_file "${SRC}/patch/misc/general-packaging-4.4.y-rk3399.patch" "applying"
		else
			process_patch_file "${SRC}/patch/misc/general-packaging-4.4.y-rockchip64.patch" "applying"
		fi
	fi

	if [[ "${version}" == "4.4."* ]] && [[ "$LINUXFAMILY" == rockchip || "$LINUXFAMILY" == rk322x ]]; then
                display_alert "Adjusting" "packaging" "info"
                cd "$kerneldir" || exit
                process_patch_file "${SRC}/patch/misc/general-packaging-4.4.y.patch" "applying"
        fi

	if [[ "${version}" == "4.9."* ]] && [[ "$LINUXFAMILY" == meson64 || "$LINUXFAMILY" == odroidc4 ]]; then
		display_alert "Adjusting" "packaging" "info"
		cd "$kerneldir" || exit
		process_patch_file "${SRC}/patch/misc/general-packaging-4.9.y.patch" "applying"
	fi

	#
	# Linux splash file
	#

	if linux-version compare "${version}" ge 5.10 && [ $SKIP_BOOTSPLASH != yes ]; then

		display_alert "Adding" "Kernel splash file" "info"

		process_patch_file "${SRC}/patch/misc/bootsplash-5.16.y-0000-Revert-fbcon-Avoid-cap-set-but-not-used-warning.patch" "applying"
		process_patch_file "${SRC}/patch/misc/bootsplash-5.16.y-0001-Revert-fbcon-Add-option-to-enable-legacy-hardware-ac.patch" "applying"

		if linux-version compare "${version}" ge 5.15; then
			process_patch_file "${SRC}/patch/misc/bootsplash-5.16.y-0002-Revert-vgacon-drop-unused-vga_init_done.patch" "applying"
		fi

		process_patch_file "${SRC}/patch/misc/bootsplash-5.16.y-0003-Revert-vgacon-remove-software-scrollback-support.patch" "applying"
		process_patch_file "${SRC}/patch/misc/bootsplash-5.16.y-0004-Revert-drivers-video-fbcon-fix-NULL-dereference-in-f.patch" "applying"
		process_patch_file "${SRC}/patch/misc/bootsplash-5.16.y-0005-Revert-fbcon-remove-no-op-fbcon_set_origin.patch" "applying"
		process_patch_file "${SRC}/patch/misc/bootsplash-5.16.y-0006-Revert-fbcon-remove-now-unusued-softback_lines-curso.patch" "applying"
		process_patch_file "${SRC}/patch/misc/bootsplash-5.16.y-0007-Revert-fbcon-remove-soft-scrollback-code.patch" "applying"

		process_patch_file "${SRC}/patch/misc/0001-bootsplash.patch" "applying"
		process_patch_file "${SRC}/patch/misc/0002-bootsplash.patch" "applying"
		process_patch_file "${SRC}/patch/misc/0003-bootsplash.patch" "applying"
		process_patch_file "${SRC}/patch/misc/0004-bootsplash.patch" "applying"
		process_patch_file "${SRC}/patch/misc/0005-bootsplash.patch" "applying"
		process_patch_file "${SRC}/patch/misc/0006-bootsplash.patch" "applying"
		process_patch_file "${SRC}/patch/misc/0007-bootsplash.patch" "applying"
		process_patch_file "${SRC}/patch/misc/0008-bootsplash.patch" "applying"
		process_patch_file "${SRC}/patch/misc/0009-bootsplash.patch" "applying"
		process_patch_file "${SRC}/patch/misc/0010-bootsplash.patch" "applying"
		process_patch_file "${SRC}/patch/misc/0011-bootsplash.patch" "applying"
		process_patch_file "${SRC}/patch/misc/0012-bootsplash.patch" "applying"

	fi

	#
	# mac80211 wireless driver injection features from Kali Linux
	#

	if linux-version compare "${version}" ge 5.4 && [ $EXTRAWIFI == yes ]; then

		display_alert "Adding" "Wireless package injections for mac80211 compatible chipsets" "info"
		if linux-version compare "${version}" ge 5.9; then
			process_patch_file "${SRC}/patch/misc/kali-wifi-injection-1-v5.9-post.patch" "applying"
		else
			process_patch_file "${SRC}/patch/misc/kali-wifi-injection-1-pre-v5.9.patch" "applying"
		fi
		process_patch_file "${SRC}/patch/misc/kali-wifi-injection-2.patch" "applying"
		process_patch_file "${SRC}/patch/misc/kali-wifi-injection-3.patch" "applying"

	fi

	# AUFS - advanced multi layered unification filesystem for Kernel > 5.1
	#
	# Older versions have AUFS support with a patch

	if linux-version compare "${version}" ge 5.1 && linux-version compare "${version}" le 5.17 && [ "$AUFS" == yes ]; then

		# attach to specifics tag or branch
		local aufstag
		aufstag=$(echo "${version}" | cut -f 1-2 -d ".")

		# manual overrides
		if linux-version compare "${version}" ge 5.4.3 && linux-version compare "${version}" le 5.5 ; then aufstag="5.4.3"; fi
		if linux-version compare "${version}" ge 5.10.82 && linux-version compare "${version}" le 5.11 ; then aufstag="5.10.82"; fi
		if linux-version compare "${version}" ge 5.15.5 && linux-version compare "${version}" le 5.16 ; then aufstag="5.15.5"; fi

		# check if Mr. Okajima already made a branch for this version
		improved_git ls-remote --exit-code --heads $GITHUB_SOURCE/sfjro/aufs5-standalone "aufs${aufstag}" >/dev/null

		if [ "$?" -ne "0" ]; then
			# then use rc branch
			aufstag="5.x-rcN"
			improved_git ls-remote --exit-code --heads $GITHUB_SOURCE/sfjro/aufs5-standalone "aufs${aufstag}" >/dev/null
		fi

		if [ "$?" -eq "0" ]; then

			display_alert "Adding" "AUFS ${aufstag}" "info"
			local aufsver="branch:aufs${aufstag}"
			fetch_from_repo "$GITHUB_SOURCE/sfjro/aufs5-standalone" "aufs5" "branch:${aufsver}" "yes"
			cd "$kerneldir" || exit
			process_patch_file "${SRC}/cache/sources/aufs5/${aufsver#*:}/aufs5-kbuild.patch" "applying"
			process_patch_file "${SRC}/cache/sources/aufs5/${aufsver#*:}/aufs5-base.patch" "applying"
			process_patch_file "${SRC}/cache/sources/aufs5/${aufsver#*:}/aufs5-mmap.patch" "applying"
			process_patch_file "${SRC}/cache/sources/aufs5/${aufsver#*:}/aufs5-standalone.patch" "applying"
			cp -R "${SRC}/cache/sources/aufs5/${aufsver#*:}"/{Documentation,fs} .
			cp "${SRC}/cache/sources/aufs5/${aufsver#*:}"/include/uapi/linux/aufs_type.h include/uapi/linux/

		fi
	fi




	# WireGuard VPN for Linux 3.10 - 5.5
	if linux-version compare "${version}" ge 3.10 && linux-version compare "${version}" le 5.5 && [ "${WIREGUARD}" == yes ]; then

		# attach to specifics tag or branch
		local wirever="branch:master"

		display_alert "Adding" "WireGuard VPN for Linux 3.10 - 5.5 ${wirever} " "info"
		fetch_from_repo "https://git.zx2c4.com/wireguard-linux-compat" "wireguard" "${wirever}" "yes"

		cd "$kerneldir" || exit
		rm -rf "$kerneldir/net/wireguard"
		cp -R "${SRC}/cache/sources/wireguard/${wirever#*:}/src/" "$kerneldir/net/wireguard"
		sed -i "/^obj-\\\$(CONFIG_NETFILTER).*+=/a obj-\$(CONFIG_WIREGUARD) += wireguard/" \
		"$kerneldir/net/Makefile"
		sed -i "/^if INET\$/a source \"net/wireguard/Kconfig\"" \
		"$kerneldir/net/Kconfig"
		# remove duplicates
		[[ $(grep -c wireguard "$kerneldir/net/Makefile") -gt 1 ]] && \
		sed -i '0,/wireguard/{/wireguard/d;}' "$kerneldir/net/Makefile"
		[[ $(grep -c wireguard "$kerneldir/net/Kconfig") -gt 1 ]] && \
		sed -i '0,/wireguard/{/wireguard/d;}' "$kerneldir/net/Kconfig"
		# headers workaround
		display_alert "Patching WireGuard" "Applying workaround for headers compilation" "info"
		sed -i '/mkdir -p "$destdir"/a mkdir -p "$destdir"/net/wireguard; \
		touch "$destdir"/net/wireguard/{Kconfig,Makefile} # workaround for Wireguard' \
		"$kerneldir/scripts/package/builddeb"

	fi

	if linux-version compare $version ge 4.4 && linux-version compare $version lt 5.8; then
		display_alert "Adjusting" "Framebuffer driver for ST7789 IPS display" "info"
		process_patch_file "${SRC}/patch/misc/fbtft-st7789v-invert-color.patch" "applying"
	fi

}
