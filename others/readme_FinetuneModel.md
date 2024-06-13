## OLLMA+MaxKB使用

### OLLAMA使用

1. 项目地址：https://www.ollama.com/
2. 下载安装：curl -fsSL https://ollama.com/install.sh | sh
3. 确认是否运行起来：``ollama list ``



### MaxKB使用

1. 项目地址：https://github.com/1Panel-dev/MaxKB

2. 安装并运行：

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

### LLAMA-factory

1. 项目地址：https://github.com/hiyouga/LLaMA-Factory

2. 下载安装：git clone git@github.com:hiyouga/LLaMA-Factory.git

3. 数据集准备：

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

4. 模型准备，譬如我们要微调qwen-1.5-7B-chat

   - 下载脚本``mirror_download.py``

   - 下载位置：登陆https://huggingface.co/，搜索模型名称，选择files and versions,复制浏览器地址https://huggingface.co/Qwen/Qwen1.5-7B-Chat/tree/main
   
   - 下载命令 python mirror_download.py https://huggingface.co/Qwen/Qwen2-7B-Instruct/tree/main
     tips：因为下载过程很长，可以尝试使用tmux 来进行下载
   
5. 模型微调

   - 启动训练界面

     ```sh
     llamafactory-cli webui
     ```

     ![ 2024-06-12 17.34.01@2x.png](https://s2.loli.net/2024/06/13/cAqfS2aBguU9Ekx.png)

6. 参数说明

   - Model Name：我们下载模型的名称，如qwen-1.5-7B-chat
   - Model Path：刚才我们下载模型的位置
   - Finetuned method： 指定lora
   - data path: 刚才创建json的文件位置
   - output dir：训练生成结果位置，记住这个位置
   - 点击start

7. 训练如果失败，可以在刚才output dir找到训练参数，此为``saves/Qwen1.5-7B-Chat/lora/train_2024-06-11-18-05-15 ``,然后重新训练

   ```sh
   llamafactory-cli train saves/Qwen1.5-7B-Chat/lora/train_2024-06-11-16-24-32/trainer_config.yaml
   ```

   - 注意如果该文件夹中除running_log.txt, trainer_config.yaml两个文件之外的其他文件，需要清空其他文件

8. 推理模型

   - 在examples/inference中创建qwen7b-chat_lora_sft.yaml

     ```yaml
     model_name_or_path: /home/supervisor/model/Qwen/Qwen1.5-7B-Chat	#下载模型位置
     adapter_name_or_path: /home/supervisor/project/LLaMA-Factory/saves/Qwen1.5-7B-Chat/lora/train_2024-06-11-18-05-15	# 这个就是刚才的output_dir
     template: qwen
     finetuning_type: lora
     ```

   - 推理模型,即可开始对话，输入exit退出

     ```sh
     llamafactory-cli chat examples/inference/qwen7b-chat_lora_sft.yaml
     ```

9. 整合模型

   - 在examples/inference中创建dcling_lora_sft.yanl

   ```yaml
   ### Note: DO NOT use quantized model or quantization_bit when merging lora adapters
   
   ### model
   model_name_or_path: /home/supervisor/model/Qwen/Qwen1.5-7B-Chat
   adapter_name_or_path: /home/supervisor/project/LLaMA-Factory/saves/Qwen1.5-7B-Chat/lora/train_2024-06-11-18-05-15
   template: qwen
   finetuning_type: lora
   
   ### export
   export_dir: models/dcling_qwen_1.5_7B_chat
   export_size: 2
   export_device: cpu
   export_legacy_format: false
   
   ```

   - 融合模型，模型将会在models文件夹看到

     ```sh
     llamafactory-cli export examples/merge_lora/dcling_lora_sft.yaml
     ```

### llama.cpp

1. 项目地址：https://github.com/ggerganov/llama.cpp

2. 项目安装：可以参看这里：https://ollama.fan/getting-started/import/#setup

   ```sh
   #First, clone the ollama/ollama repo:
   git clone git@github.com:ollama/ollama.git ollama
   cd ollama
   
   #and then fetch its llama.cpp submodule:
   git submodule init
   git submodule update llm/llama.cpp
   
   #Next, install the Python dependencies:
   python3 -m venv llm/llama.cpp/.venv
   source llm/llama.cpp/.venv/bin/activate
   pip install -r llm/llama.cpp/requirements.txt
   
   #Then build the quantize tool:
   make -C llm/llama.cpp quantize
   ```

3. 将刚才融合好的模型进行转换 

   ```sh
   python llm/llama.cpp/convert.py ./model --outtype f16 --outfile converted.bin
   ```

4. 量化converted.bin

   ```sh
   llm/llama.cpp/quantize converted.bin quantized.bin q4_0
   ```

5. 创建Modelfile

   ```sh
   FROM quantized.bin
   
   TEMPLATE "[INST] {{ .Prompt }} [/INST]"
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