# Changelog

## 0.1.1 (2026-08-27)

- 修复：README 安装方式统一为三方式（方式一 npx `-g` / `--dir` 指定目录，方式二 install.sh（`--agent` 仅示例用），方式三手动复制+目录表），删除 npx 固定 `--agent codex` 的写法；README 中英双版同步。
- 对齐：package.json / SKILL.md / CHANGELOG / README / references/rules.md 的版本锚点统一到 v0.1.1；引擎 `version` 输出与测试断言同步。
- 引擎无功能变更，测试保持 52/52。

## 0.1.0 (2026-08-27)

- 初始版本：零依赖供应链依赖校验引擎（Python 3.8+ 标准库，纯本地离线）。
- 生态：npm（package.json + package-lock v1/v2/v3 + npm-shrinkwrap + .npmrc 作用域仓库）、
  Python（requirements*.txt + pyproject.toml（PEP 621 / poetry）+ poetry.lock + Pipfile / Pipfile.lock）、
  Maven（pom.xml 基础：未固定版本 / SNAPSHOT / 可疑仓库 URL）。
- 检测：
  - 依赖混淆：scope 私有仓库配置 vs 实际解析仓库、同一包多仓库混合、可疑仓库 URL（http / IP / localhost）、
    pip extra-index 公共回退、poetry secondary 源、Pipfile 公私源混配；
  - lockfile 一致性：清单条目缺失 / 版本范围不满足（npm semver + PEP 440）/ 根信息不一致 /
    悬空引用 / 缺 integrity / 同版本多来源冲突；
  - 卫生：缺失锁文件 / 未固定版本（* / latest）/ Maven SNAPSHOT；
  - typo-squat：依赖名与知名 npm / PyPI 包编辑距离 ≤ 2 提示。
- SBOM-lite：CycloneDX 1.5 子集 JSON（components + dependencies + purl，scope / direct / resolved / integrity）。
- 输出：text / JSON / CSV；scan 退出码 0（干净）/ 1（有发现）/ 4（错误），--gate 可调 CI 闸门。
- 测试：52/52 全绿。
