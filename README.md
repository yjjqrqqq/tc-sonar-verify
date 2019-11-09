# tc-sonar-verify
TeamCity下Sonar结果验证，基于Java

## 示例
TeamCity中使用以下命令集成，若不满足条件，即失败
参见 TeamCity [TeamCity Service Message](https://confluence.jetbrains.com/display/TCD9/Build+Script+Interaction+with+TeamCity?&_ga=2.40264418.1506726782.1573278037-1889108018.1569807688#BuildScriptInteractionwithTeamCity-reportingMessagesForBuildLogReportingMessagesForBuildLog)
>javar -jar tc-sonar-verify.jar url=http://sonar.yjjqrqqq.com  component=com.yjjqrqqq.test:test  maxBugs=0  minCoverage=70  maxVulnerabilities=0

不允许bugs和漏洞，代码覆盖率至少70%
##参数说明
+ url: sonar地址 
+ component: 项目标识，通常是  package:id 的形式
+ maxBugs: 允许最大的bugs数
+ minCoverage: 允许最小的代码覆盖率
+ maxVulnerabilities :允许最大的漏洞数

