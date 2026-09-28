package com.example.attacksimulator.attack;

import java.util.List;

public final class DictionaryPasswordList {

	private DictionaryPasswordList() {
	}

	// =========================================================
	// 過去の漏洩パスワード統計
	// 4桁パスワード Top100
	//
	// 4桁パスワードの辞書攻撃用リスト
	// =========================================================
	private static final List<Entry> TOP_100 =
			List.of(
					new Entry(1, "1234", "連番"),
					new Entry(2, "1111", "ぞろ目"),
					new Entry(3, "6969", "繰り返し"),
					new Entry(4, "1212", "繰り返し"),
					new Entry(5, "0000", "ぞろ目"),
					new Entry(6, "1313", "繰り返し"),
					new Entry(7, "1989", "年"),
					new Entry(8, "1990", "年"),
					new Entry(9, "1987", "年"),
					new Entry(10, "2005", "年"),
					new Entry(11, "7777", "ぞろ目"),
					new Entry(12, "1991", "年"),
					new Entry(13, "2121", "繰り返し"),
					new Entry(14, "1988", "年"),
					new Entry(15, "2323", "繰り返し"),
					new Entry(16, "2006", "年"),
					new Entry(17, "2468", "偶数"),
					new Entry(18, "1986", "年"),
					new Entry(19, "1985", "年"),
					new Entry(20, "2222", "ぞろ目"),
					new Entry(21, "5150", "数字パターン"),
					new Entry(22, "4444", "ぞろ目"),
					new Entry(23, "2007", "年"),
					new Entry(24, "1010", "繰り返し"),
					new Entry(25, "1992", "年"),
					new Entry(26, "1122", "繰り返し"),
					new Entry(27, "8888", "ぞろ目"),
					new Entry(28, "2001", "年"),
					new Entry(29, "1982", "年"),
					new Entry(30, "1984", "年"),
					new Entry(31, "1221", "繰り返し"),
					new Entry(32, "1983", "年"),
					new Entry(33, "3333", "ぞろ目"),
					new Entry(34, "5555", "ぞろ目"),
					new Entry(35, "2424", "繰り返し"),
					new Entry(36, "2008", "年"),
					new Entry(37, "2525", "繰り返し"),
					new Entry(38, "1981", "年"),
					new Entry(39, "5683", "数字パターン"),
					new Entry(40, "1121", "数字パターン"),
					new Entry(41, "9999", "ぞろ目"),
					new Entry(42, "1977", "年"),
					new Entry(43, "2002", "年"),
					new Entry(44, "1213", "数字パターン"),
					new Entry(45, "2004", "年"),
					new Entry(46, "2020", "年"),
					new Entry(47, "2009", "年"),
					new Entry(48, "2003", "年"),
					new Entry(49, "2000", "年"),
					new Entry(50, "1432", "逆順系"),
					new Entry(51, "1999", "年"),
					new Entry(52, "1230", "連番"),
					new Entry(53, "1226", "数字パターン"),
					new Entry(54, "1223", "数字パターン"),
					new Entry(55, "1210", "数字パターン"),
					new Entry(56, "1020", "繰り返し"),
					new Entry(57, "2010", "年"),
					new Entry(58, "1993", "年"),
					new Entry(59, "1979", "年"),
					new Entry(60, "1978", "年"),
					new Entry(61, "1515", "繰り返し"),
					new Entry(62, "1231", "連番"),
					new Entry(63, "2112", "繰り返し"),
					new Entry(64, "1717", "繰り返し"),
					new Entry(65, "1414", "繰り返し"),
					new Entry(66, "1218", "数字パターン"),
					new Entry(67, "1214", "数字パターン"),
					new Entry(68, "1980", "年"),
					new Entry(69, "1616", "繰り返し"),
					new Entry(70, "1224", "数字パターン"),
					new Entry(71, "1220", "数字パターン"),
					new Entry(72, "1216", "数字パターン"),
					new Entry(73, "1127", "数字パターン"),
					new Entry(74, "1124", "数字パターン"),
					new Entry(75, "1105", "日付系"),
					new Entry(76, "1024", "数字パターン"),
					new Entry(77, "1021", "数字パターン"),
					new Entry(78, "1025", "数字パターン"),
					new Entry(79, "5678", "連番"),
					new Entry(80, "1225", "数字パターン"),
					new Entry(81, "1211", "数字パターン"),
					new Entry(82, "1128", "数字パターン"),
					new Entry(83, "1123", "数字パターン"),
					new Entry(84, "0123", "連番"),
					new Entry(85, "1228", "数字パターン"),
					new Entry(86, "1022", "数字パターン"),
					new Entry(87, "1001", "数字パターン"),
					new Entry(88, "7410", "数字パターン"),
					new Entry(89, "5656", "繰り返し"),
					new Entry(90, "1126", "数字パターン"),
					new Entry(91, "4321", "逆順"),
					new Entry(92, "3232", "繰り返し"),
					new Entry(93, "2626", "繰り返し"),
					new Entry(94, "1994", "年"),
					new Entry(95, "1972", "年"),
					new Entry(96, "1023", "数字パターン"),
					new Entry(97, "6666", "ぞろ目"),
					new Entry(98, "2580", "数字パターン"),
					new Entry(99, "1437", "数字パターン"),
					new Entry(100, "1229", "数字パターン")
					);

	/**
	 * 4桁パスワード Top100 を取得する。
	 *
	 * @return Top100の辞書エントリ
	 */
	public static List<Entry> getTop100() {
		return TOP_100;
	}

	/**
	 * 指定された件数までのパスワードを取得する。
	 *
	 * @param maxEntries 最大取得件数
	 * @return パスワード一覧
	 */
	public static List<String> getPasswords(int maxEntries) {

		int limit = Math.max(
				1,
				Math.min(maxEntries, TOP_100.size()));

		return TOP_100.stream()
				.limit(limit)
				.map(Entry::password)
				.toList();
	}

	/**
	 * 辞書パスワードのエントリ。
	 */
	public record Entry(
			int rank,
			String password,
			String category) {
	}
}