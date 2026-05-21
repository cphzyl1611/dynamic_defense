# 多模态网络动态防御测试原型（对应测试用例 34/35/36）

这个原型用于把测试大纲 3.4 的三个动态防御条目先跑通：

- `strategy_loader.py`：测试用例 34，加载防御策略库并输出策略元数据。
- `feature_analyzer.py`：测试用例 35，对 CICIDS 2017 风格流量特征做向量化与威胁模板匹配。
- `attack_defender.py`：测试用例 36，在持续攻击数据窗口上触发策略选择、策略切换和在线收益更新。

## 目录

```text
configs/strategies.yaml              # 防御策略库配置
configs/feature_templates.yaml        # 特征字段与启发式模板
src/dynamic_defense/                  # 核心模块
strategy_loader.py                    # 用例34入口
feature_analyzer.py                   # 用例35入口
attack_defender.py                    # 用例36入口
scripts/make_sample_cicids.py         # 生成可跑通的示例数据
reports/                              # 运行输出
```

## 本地快速运行

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python scripts/make_sample_cicids.py --out data/sample_cicids.csv
python strategy_loader.py --config configs/strategies.yaml --db data/policies.sqlite
python feature_analyzer.py --input data/sample_cicids.csv --build-templates --limit 300
python attack_defender.py --input data/sample_cicids.csv --build-templates --window-size 100 --limit 700
```

运行后重点查看：

- `reports/strategy_metadata.json`：策略 ID、模型类型、最后更新时间等元数据。
- `reports/feature_match_report.csv`：每条流记录的特征匹配结果。
- `reports/dynamic_defense_events.csv`：每个时间窗口是否触发策略调整、选择的策略、奖励和动作日志。

## 替换为真实 CICIDS 2017 数据

把 CSV 放到 `data/` 下，然后执行：

```bash
python strategy_loader.py
python feature_analyzer.py --input data/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv --build-templates --limit 5000
python attack_defender.py --input data/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv --build-templates --window-size 500 --limit 50000
```

脚本兼容部分 CICIDS 新旧列名，例如 `Dst Port`/`Destination Port`、`Flow Byts/s`/`Flow Bytes/s`。

## CENI 上的落地方式

建议在 CENI 中创建一个小型试验拓扑：

```text
traffic-replay VM  ->  defense VM  ->  service/victim VM
                         |
                    controller VM
```

部署建议：

1. 在 `defense VM` 部署本项目，运行 `strategy_loader.py`、`feature_analyzer.py`、`attack_defender.py`。
2. `traffic-replay VM` 只回放已授权/离线数据集或生成 benign/attack-like 测试流，不对公网或无授权目标发起真实攻击。
3. `controller VM` 部署你们已有的 Ryu/ONOS/P4Runtime/自研控制器接口。
4. `attack_defender.py` 默认 `--adapter dry_run`，只记录动作。要联动控制器时改为：

```bash
export CENI_CONTROLLER_ENDPOINT=http://<controller-vm-ip>:8080
python attack_defender.py --input data/xxx.csv --adapter rest
```

控制器侧需要实现：

```text
POST /defense/action
Content-Type: application/json
```

请求体包含 `strategy_id`、`action`、`context`。这样可以把策略动作映射为 SDN 流表、P4 表项、VSR 路由策略、限速或隔离操作。

## 现在这版的边界

- 这是一版“测试大纲可运行原型”，不是最终生产级 IDS/IPS。
- 在线优化采用可解释的 actor-critic-like bandit 近似：actor 负责按攻击类型产生候选策略，critic 使用运行奖励评估策略收益。
- 如果老师要求严格的 A2C/PPO，可以保持脚本入口不变，只替换 `src/dynamic_defense/optimizer.py`。
