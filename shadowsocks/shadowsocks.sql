
SET NAMES utf8;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
--  Table structure for `bandwidth_log`
-- ----------------------------
DROP TABLE IF EXISTS `bandwidth_log`;
CREATE TABLE `bandwidth_log` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `node` varchar(255) NOT NULL,
  `port` int(11) NOT NULL,
  `data` bigint(20) NOT NULL,
  `time` int(11) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;

-- ----------------------------
--  Table structure for `user`
-- ----------------------------
DROP TABLE IF EXISTS `user`;
CREATE TABLE `user` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `u_email` varchar(32) NOT NULL COMMENT '邮件',
  `u_pwd` varchar(32) NOT NULL COMMENT '密码',
  `u_nickname` varchar(255) NOT NULL COMMENT '昵称',
  `u_status` tinyint(4) NOT NULL DEFAULT '1' COMMENT '用户状态',
  `ss_port` int(11) NOT NULL COMMENT 'ss端口',
  `ss_pwd` varchar(32) NOT NULL COMMENT 'ss密码',
  `b_usage` bigint(20) NOT NULL COMMENT '使用流量',
  `b_max` bigint(20) NOT NULL COMMENT '可使用最大流量',
  `update_time` int(11) NOT NULL DEFAULT '0' COMMENT '更新时间',
  PRIMARY KEY (`id`),
  UNIQUE KEY `pk_ss_port` (`ss_port`),
  UNIQUE KEY `pk_u_email` (`u_email`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 ROW_FORMAT=COMPACT;

SET FOREIGN_KEY_CHECKS = 1;
