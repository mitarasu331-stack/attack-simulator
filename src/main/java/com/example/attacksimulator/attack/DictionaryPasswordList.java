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
					new Entry(1, "1234"),
					new Entry(2, "1111"),
					new Entry(3, "6969"),
					new Entry(4, "1212"),
					new Entry(5, "0000"),
					new Entry(6, "1313"),
					new Entry(7, "1989"),
					new Entry(8, "1990"),
					new Entry(9, "1987"),
					new Entry(10, "2005"),
					new Entry(11, "7777"),
					new Entry(12, "1991"),
					new Entry(13, "2121"),
					new Entry(14, "1988"),
					new Entry(15, "2323"),
					new Entry(16, "2006"),
					new Entry(17, "2468"),
					new Entry(18, "1986"),
					new Entry(19, "1985"),
					new Entry(20, "2222"),
					new Entry(21, "5150"),
					new Entry(22, "4444"),
					new Entry(23, "2007"),
					new Entry(24, "1010"),
					new Entry(25, "1992"),
					new Entry(26, "1122"),
					new Entry(27, "8888"),
					new Entry(28, "2001"),
					new Entry(29, "1982"),
					new Entry(30, "1984"),
					new Entry(31, "1221"),
					new Entry(32, "1983"),
					new Entry(33, "3333"),
					new Entry(34, "5555"),
					new Entry(35, "2424"),
					new Entry(36, "2008"),
					new Entry(37, "2525"),
					new Entry(38, "1981"),
					new Entry(39, "5683"),
					new Entry(40, "1121"),
					new Entry(41, "9999"),
					new Entry(42, "1977"),
					new Entry(43, "2002"),
					new Entry(44, "1213"),
					new Entry(45, "2004"),
					new Entry(46, "2020"),
					new Entry(47, "2009"),
					new Entry(48, "2003"),
					new Entry(49, "2000"),
					new Entry(50, "1432"),
					new Entry(51, "1999"),
					new Entry(52, "1230"),
					new Entry(53, "1226"),
					new Entry(54, "1223"),
					new Entry(55, "1210"),
					new Entry(56, "1020"),
					new Entry(57, "2010"),
					new Entry(58, "1993"),
					new Entry(59, "1979"),
					new Entry(60, "1978"),
					new Entry(61, "1515"),
					new Entry(62, "1231"),
					new Entry(63, "2112"),
					new Entry(64, "1717"),
					new Entry(65, "1414"),
					new Entry(66, "1218"),
					new Entry(67, "1214"),
					new Entry(68, "1980"),
					new Entry(69, "1616"),
					new Entry(70, "1224"),
					new Entry(71, "1220"),
					new Entry(72, "1216"),
					new Entry(73, "1127"),
					new Entry(74, "1124"),
					new Entry(75, "1105"),
					new Entry(76, "1024"),
					new Entry(77, "1021"),
					new Entry(78, "1025"),
					new Entry(79, "5678"),
					new Entry(80, "1225"),
					new Entry(81, "1211"),
					new Entry(82, "1128"),
					new Entry(83, "1123"),
					new Entry(84, "0123"),
					new Entry(85, "1228"),
					new Entry(86, "1022"),
					new Entry(87, "1001"),
					new Entry(88, "7410"),
					new Entry(89, "5656"),
					new Entry(90, "1126"),
					new Entry(91, "4321"),
					new Entry(92, "3232"),
					new Entry(93, "2626"),
					new Entry(94, "1994"),
					new Entry(95, "1972"),
					new Entry(96, "1023"),
					new Entry(97, "6666"),
					new Entry(98, "2580"),
					new Entry(99, "1437"),
					new Entry(100, "1229")
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
			String password) {
	}
}