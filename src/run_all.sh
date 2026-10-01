#!/bin/bash
# Paper A grids (deterministic, resumable). Needs data/, models/qwen1.5b and models/adapters/{sft,dpo3,dpo2}.pt
cd "$(dirname "$0")"
export PYTHONHASHSEED=0
W=${W:-14}
serve() { python llm_server.py $1 > ../results/llm_server.log 2>&1 & until grep -q "ready" ../results/llm_server.log; do sleep 5; done; }
stop() { pkill -f llm_server.py 2>/dev/null || powershell -Command "Get-CimInstance Win32_Process -Filter \"name='python.exe'\" | Where-Object { \$_.CommandLine -like '*llm_server*' } | ForEach-Object { Stop-Process -Id \$_.ProcessId -Force }"; sleep 8; }
NL=none,portdrop,template,vtemplate,vtemplate_D
for g in A_main A_m1 A_m4 A_det; do python run_exp.py $g --only $NL --workers 10; done
SFT="llm,verimit,verimit_D,vm_no_conflict,vm_no_reach,vm_no_blast,vm_no_scope,vm_no_ttl,vm_no_semantics,vm_no_twin,vm_no_cex,vm_no_prune,vm_provisional,vm_speed2,vm_speed5,vm_speed10,vm_speed20,vm_sft_val"
serve "--merge sft=../models/adapters/sft.pt"
for g in A_main A_m1 A_speed A_abl A_det A_val; do python run_exp.py $g --only $SFT --workers $W; done
python run_exp.py A_m4 --only verimit,verimit_D --workers $W
stop
serve ""
python run_exp.py A_abl --only vm_base_fewshot,llm_base_fewshot --maxseed 3 --workers $W
stop
serve "--merge dpo3=../models/adapters/dpo3.pt"; python run_exp.py A_val --only vm_dpo --workers $W; python run_exp.py A_abl --only vm_dpo --workers $W; stop
serve "--merge dpo2=../models/adapters/dpo2.pt"; python run_exp.py A_val --only vm_dpo2 --workers $W; stop
echo ALLDONE
