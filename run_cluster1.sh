#! /bin/bash

appName=auth_hub

pathFile=$(realpath $0)
pathDir=$(dirname $pathFile)

cd $pathDir


find="\[\'auth_hub_cluster1\@mykhailo-pc1\'\]"
insert="\[\'auth_hub_main\@mykhailo-pc1\'\]"
perl -pi -e 's/'$find'/'$insert'/g' config/sys.config

find1="auth_hub_main"
insert1="auth_hub_cluster1"
perl -pi -e 's/'$find1'/'$insert1'/g' config/vm.args


rebar3 as prod release
cd ./_build/prod/rel/$appName/bin/
./$appName console