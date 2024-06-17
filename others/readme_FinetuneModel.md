## OLLMA+MaxKB使用

### OLLAMA使用

1. 项目地址：https://www.ollama.com/
2. 下载安装：curl -fsSL https://ollama.com/install.sh | sh
3. 确认是否运行起来：``ollama list ``和``curl 127.0.0.1:11434``



### MaxKB使用

1. 项目地址：https://github.com/1Panel-dev/MaxKB

2. 安装并运行：

   tips：最近国内的docker image镜像被封掉了，可以找其他的方式，譬如给docker挂代理或者本地上传

   ```sh
   docker run -d --name=maxkb -p 8080:8080 -v ~/.maxkb:/var/lib/postgresql/data 1panel/maxkb
   # 8080端口可能会和nginx冲突，可以-p 8081:8080
   
   # 用户名: admin
   # 密码: MaxKB@123..
   ```

3. 修改ollama service并重载ollama使MaxKB可以访问

   ```sh
   cd /etc/systemd/system
   vim ollama.service 
   # 在ExecStart=/usr/local/bin/ollama serve上加一句
   # Environment="OLLAMA_HOST=0.0.0.0:11434"
   
   ```

4. 检查是否MaxKB可以访问ollama service

   ```sh
   docker exec -it maxkb bash
   curl http://xxx.xxx.xxx.xxx:11434
   #Ollama is running
   ```

5. 浏览器访问MaxKB ``http://ip:8080``

   - 创建应用

     ![ 2024-06-12 17.10.25@2x.png](https://s2.loli.net/2024/06/13/dHw4S8Kj1zkIGW7.png)

     主要是AI模型的设置和提示词的设置

   - AI模型设置

     ![ 2024-06-12 17.14.21@2x.png](https://s2.loli.net/2024/06/13/2ovnsSX8qHtakhm.png)

     - 模型名称：随便填

     - 模型类型：应该只有大语言模型

     - 基础模型：请选择ollama list结果中的一项

       ```sh
       /etc/syst/system ❯ ollama list                                               
       NAME                            ID              SIZE    MODIFIED    
       example:latest                  1bdaaf5089a4    15 GB   2 hours ago
       llama2-chinese:13b              990f930d55c5    7.4 GB  8 days ago 
       maxkb/baichuan2:13b-chat        22b2c2a9121b    27 GB   2 weeks ago
       qwen:32b                        26e7e8447f5d    18 GB   2 weeks ago
       qwen:72b                        e1c64582de5c    41 GB   2 weeks ago
       llama3:8b                       365c0bd3c000    4.7 GB  2 weeks ago
       qwen:7b                         2091ee8c8d8f    4.5 GB  2 weeks ago
       ```

     - API域名：可以更换IP,端口别动

     - API key：随便填

### 微调大模型

### Miniconda---python 环境准备

1. 下载miniconda安装包

   ```sh
   wget -c https://mirrors.tuna.tsinghua.edu.cn/anaconda/miniconda/Miniconda3-latest-Linux-x86_64.sh
   ```

2. 安装miniconda

   ```sh
   sh Miniconda3-latest-Linux-x86_64.sh
   ## 提示项建议均选择 yes，接受 LICENSE 以及配置 conda 初始化
   ## 最后一步也输入yes
   ## 新打开一个Terminal窗口，就可以看到每行前面显示了(base) test@f1:~$，这里(base) 表示conda的默认虚拟环境。
   ```

3. conda 和 pip 换源

   ```sh
   conda config --add channels https://mirrors.tuna.tsinghua.edu.cn/anaconda/pkgs/free/
   conda config --add channels https://mirrors.tuna.tsinghua.edu.cn/anaconda/pkgs/main/
   conda config --set show_channel_urls yes 
   
   pip install pip -U
   pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple
   ```

4. tips：可以``pip install nvitop``在terminal输入``nvitop``便可以实时监控显卡状态以查看是否爆内存

### LLAMA-factory

1. 项目地址：https://github.com/hiyouga/LLaMA-Factory

2. 下载安装：git clone git@github.com:hiyouga/LLaMA-Factory.git

   tips: 如何git 不下来，请检查github中账户是否含有当前机器的ssh key[看这里](https://blog.csdn.net/weixin_42310154/article/details/118340458)

3. 环境准备``pip install -e ".[torch,metrics]"``

4. 数据集准备：

   - 请在data/文件夹下新建json文件如``dcling_ques_zh.json``

   - 填充``dcling_ques_zh.json``

     ```json
     [
         {
             "instruction":"识别下列句子中的可能的对象实体,时间实体,指标实体:",
             "input":"请查看互联网入口链路过去24小时的流量趋势情况",
             "output":"对象实体:互联网入口;时间实体:过去24小时;指标实体:流量",
             "system":"你是一个精通网络流量分析和命名实体识别的标注人员"
         },
         {
             "instruction":"识别下列句子中的可能的对象实体,时间实体,指标实体:",
             "input":"请查看互联网入口链路今天早上的网络延迟情况",
             "output":"对象实体:互联网入口;时间实体:今天早上;指标实体:网络延迟",
             "system":"你是一个精通网络流量分析和命名实体识别的标注人员"
         },
         {
             "instruction":"识别下列句子中的可能的对象实体,时间实体,指标实体:",
             "input":"想要知道办公网络昨天一天的带宽利用率",
             "output":"对象实体:办公网络;时间实体:昨天一天;指标实体:带宽利用率",
             "system":"你是一个精通网络流量分析和命名实体识别的标注人员"
         }
     ]
     ```

     - instruction请不要随意改动，input为提问问题，output为识别的实体，格式需要对齐，system请不要随意变动

   - 将``dcling_ques_zh.json``登记到data/dataset_info.json中

     ```json
       "dcling_ques_zh":{
         "file_name":"dcling_ques_zh.json",
         "columns":{
           "prompt":"instruction",
           "query":"input",
           "response":"output",
           "system":"system"
         }
     ```

5. 模型准备，譬如我们要微调qwen-1.5-7B-chat

   - 下载脚本``mirror_download.py``

   - 下载位置：登陆https://huggingface.co/，搜索模型名称，选择files and versions,复制浏览器地址https://huggingface.co/Qwen/Qwen1.5-7B-Chat/tree/main

   - 下载命令 python mirror_download.py https://huggingface.co/Qwen/Qwen2-7B-Instruct/tree/main
     tips：因为下载过程很长，可以尝试使用tmux 来进行下载
     
     tips：只要你能找到方式下载就行，国内的魔塔社区也能下载

6. 模型微调sft

   - 准备训练模型config

     ```yaml
     #### location at examples/train_qlora/qwen1.5-32B-chat_lora-sft_bitsandbytes.yaml
     
     ### model
     model_name_or_path: /home/supervisor/model/Qwen/Qwen1.5-32B-Chat	##此为下载好的模型位置
     quantization_bit: 4
     
     ### method
     stage: sft
     do_train: true
     finetuning_type: lora
     lora_target: all
     
     ### dataset
     dataset: dcling_ques_zh		## 此为刚才准备好的数据名称
     template: qwen				## 此为模型类型，因为我们用的qwen,所以填写qwen
     cutoff_len: 1024
     max_samples: 1000
     overwrite_cache: true
     preprocessing_num_workers: 16
     
     ### output
     output_dir: saves/qwen1.5-32b/lora/sft		## 此为输出lora 权重位置
     logging_steps: 10
     save_steps: 500
     plot_loss: true
     overwrite_output_dir: true
     
     ### train
     per_device_train_batch_size: 1
     gradient_accumulation_steps: 8
     learning_rate: 1.0e-4
     num_train_epochs: 3.0
     lr_scheduler_type: cosine
     warmup_ratio: 0.1
     fp16: true
     ddp_timeout: 180000000
     
     ### eval
     val_size: 0.1
     per_device_eval_batch_size: 1
     eval_strategy: steps
     eval_steps: 500
     
     ```

   - 训练模型

     ```sh
     llamafactory-cli train examples/train_qlora/qwen1.5-32B-chat_lora-sft_bitsandbytes.yaml
     ```

   

7. 推理模型

   - 准备推理模型config

     ```yaml
     #### location at examples/inference/qwen1.5_lora_sft.yaml
     model_name_or_path: /home/supervisor/model/Qwen/Qwen1.5-32B-Chat
     adapter_name_or_path: saves/qwen1.5-32b/lora/sft
     template: qwen
     finetuning_type: lora
     ```

   - 推理模型

     ```sh
     llamafactory-cli chat examples/inference/qwen1.5_lora_sft.yaml  
     ```

   - 但由于32B模型过大，会将模型offload到内存中去，导致推理时间异常缓慢，故而这一步一般不做

8. 整合模型

   - 准备整合模型config

   ```yaml
   ### Note: DO NOT use quantized model or quantization_bit when merging lora adapters
   
   ### model
   model_name_or_path: /home/supervisor/model/Qwen/Qwen1.5-32B-Chat
   adapter_name_or_path: saves/qwen1.5-32b/lora/sft
   template: qwen
   finetuning_type: lora
   
   ### export
   export_dir: models/qwen1.5-32b
   export_size: 2
   export_device: cpu
   export_legacy_format: false
   ```

   - 整合模型

     ```sh
     llamafactory-cli export examples/merge_lora/qwen1.5_lora_sft.yaml
     ```

### llama.cpp

1. 项目地址：https://github.com/ggerganov/llama.cpp

2. 项目安装

   ```sh
   #First, clone the ollama/ollama repo:
   git clone git@github.com:ollama/ollama.git ollama
   cd ollama
   
   #Second, clone the llama.cpp repo and move it in ollama
   git clone git@github.com:ggerganov/llama.cpp.git
   mv llama.cpp ./ollama/llm
   
   #Next, install the Python dependencies:
   conda create -n llamacpp python=3.11 
   conda activate llamacpp
   pip install -r llm/llama.cpp/requirements.txt
   
   #Then build the llama.cpp:
   cd llm.llama.cpp
   make
   ```

3. 将刚才融合好的模型进行转换 ,请注意模型位置并替换

   ```sh
   python convert-hf-to-gguf.py ../../../LLaMA-Factory/models/qwen1.5-32b --outtype f16 --outfile converted.bin 
   ```

4. 将转换好的模型进行量化

   ```sh
   ./llama-quantize converted.bin quantized.bin q4_0 
   ```

5. 创建Modelfile

   ```sh
   FROM quantized.bin
   
   TEMPLATE """{{ if .System }}<|im_start|>system
   {{ .System }}<|im_end|>
   {{ end }}{{ if .Prompt }}<|im_start|>user
   {{ .Prompt }}<|im_end|>
   {{ end }}<|im_start|>assistant
   """
   ```

6. 根据Modelfile创建Model，**这里example就是创建好的模型名字，既在ollama list显示的名字，也既在maxKB中填写的模型名字**

   ```sh
   ollama create example -f Modelfile
   ```

7. 运行模型,即可开启对话

   ```sh
   ollama run example
   ```

   tips:在maxKB中运行模型不需要手动在服务器上启动模型，只需要保证模型存在即可

   

   

==========================================================================

任何问题请联系895550664@qq.com