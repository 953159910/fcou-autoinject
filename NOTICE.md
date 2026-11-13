# 第三方组件

## third_party/libForceCloseOreUI.so

- 来源：[yinghuajimew/ForceCloseOreUI-android](https://github.com/yinghuajimew/ForceCloseOreUI-android)
  （standalone / Dobby 版，`app/src/main/assets/libForceCloseOreUI_standalone.so`）
- 备选：[yinghuajimew/yinghuaji-ForceCloseOreUI](https://github.com/yinghuajimew/yinghuaji-ForceCloseOreUI)（需要配套 `libpreloader.so`）
- 版权归原作者 yinghuajimew 所有。本仓库只做「不改包、root 注入」的外壳，不修改该二进制。
- 它负责：扫 `libminecraftpe.so` 内存特征码 → `DobbyHook` oreUI 配置函数 → 按 `config.json` 写入 `mConfigs`。

仓库里的示例 APK 器（[No OreUI](https://github.com/yinghuajimew/yhjmew.no.ore.ui)）与本项目无代码复用，
仅参考了其注入点思路（`MainActivity.onCreate` 前置 `System.loadLibrary`）。
