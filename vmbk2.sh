#!/bin/bash
#backs up
#change the location below to your backup location 
backuplocation="/mnt/user/Archives/VMBackup/"

# do not alter below this line
datestamp="_"`date '+%d_%b_%Y'`
dir="$backuplocation"/vmsettings/"$datestamp"
# dont change anything below here
if [ ! -d $dir ] ; then
 
			echo "making folder for todays date $datestamp"

			# make the directory as it doesnt exist
			mkdir -vp $dir
		else
			echo "As $dir exists continuing."
			fi

echo "Saving vm xml files"
rsync -a --no-o /etc/libvirt/qemu/*xml $dir/xml/
echo "Saving ovmf nvram"
rsync -a --no-o /etc/libvirt/qemu/nvram/* $dir/nvram/
chmod -R 777 $dir
sleep 5
exit
