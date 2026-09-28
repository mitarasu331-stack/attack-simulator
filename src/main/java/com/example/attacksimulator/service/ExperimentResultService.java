package com.example.attacksimulator.service;

import java.util.List;

import jakarta.persistence.EntityManager;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.example.attacksimulator.model.ExperimentResult;
import com.example.attacksimulator.repository.ExperimentResultRepository;

@Service
public class ExperimentResultService {

	private final ExperimentResultRepository experimentResultRepository;

	private final EntityManager entityManager;

	public ExperimentResultService(
			ExperimentResultRepository experimentResultRepository,
			EntityManager entityManager) {

		this.experimentResultRepository =
				experimentResultRepository;

		this.entityManager =
				entityManager;
	}

	// =========================================================
	// 結果追加
	// =========================================================

	/**
	 * maxAttemptCountをStringで保存する版。
	 *
	 * 例：
	 * 10000
	 * 3000 → 5000
	 * 3000 → 5000 → 2000
	 * 10000 → 1000000
	 */
	public void addResult(
			String username,
			String authMethod,
			String authenticationConfiguration,
			String maxAttemptCount,
			int attemptCount,
			boolean success,
			String credential,
			long attackTimeMs) {

		ExperimentResult result =
				new ExperimentResult();

		result.setUsername(username);

		result.setAuthMethod(authMethod);

		result.setAuthenticationConfiguration(
				authenticationConfiguration);

		result.setMaxAttemptCount(
				maxAttemptCount);

		result.setAttemptCount(
				attemptCount);

		result.setSuccess(
				success);

		result.setCredential(
				credential);

		result.setAttackTimeMs(
				attackTimeMs);

		result.setExperimentDateTime(
				java.time.LocalDateTime.now());

		experimentResultRepository.save(result);
	}

	// =========================================================
	// 旧形式互換
	// =========================================================

	/**
	 * maxAttemptCountがintの既存コードとの互換用。
	 */
	public void addResult(
			String username,
			String authMethod,
			String authenticationConfiguration,
			int maxAttemptCount,
			int attemptCount,
			boolean success,
			String credential,
			long attackTimeMs) {

		addResult(
				username,
				authMethod,
				authenticationConfiguration,
				String.valueOf(maxAttemptCount),
				attemptCount,
				success,
				credential,
				attackTimeMs);
	}

	// =========================================================
	// 全結果取得
	// =========================================================

	public List<ExperimentResult> getAllResults() {

		return experimentResultRepository
				.findAllByOrderByIdAsc();
	}

	// =========================================================
	// 認証方式別結果取得
	// =========================================================

	public List<ExperimentResult>
	getResultsByAuthMethod(
			String authMethod) {

		return experimentResultRepository
				.findByAuthMethodOrderByIdAsc(
						authMethod);
	}

	// =========================================================
	// 最新結果取得
	// =========================================================

	public ExperimentResult getLatestResult() {

		return experimentResultRepository
				.findTopByOrderByIdDesc()
				.orElse(null);
	}

	// =========================================================
	// 全体集計
	// =========================================================

	/**
	 * 総実験回数
	 */
	public long getTotalExperimentCount() {

		return experimentResultRepository.count();
	}

	/**
	 * 総攻撃試行回数
	 */
	public long getTotalAttemptCount() {

		return getAllResults()
				.stream()
				.mapToLong(
						ExperimentResult::getAttemptCount)
				.sum();
	}

	/**
	 * 平均攻撃試行回数
	 */
	public double getAverageAttemptCount() {

		long total =
				getTotalExperimentCount();

		if (total == 0) {

			return 0.0;
		}

		return (double) getTotalAttemptCount()
				/ total;
	}

	// =========================================================
	// 認証方式別集計
	// =========================================================

	/**
	 * 認証方式別実験回数
	 */
	public long getExperimentCountByAuthMethod(
			String authMethod) {

		return getResultsByAuthMethod(authMethod)
				.size();
	}

	/**
	 * 認証方式別成功回数
	 */
	public long getSuccessCountByAuthMethod(
			String authMethod) {

		return getResultsByAuthMethod(authMethod)
				.stream()
				.filter(ExperimentResult::isSuccess)
				.count();
	}

	/**
	 * 認証方式別成功率
	 */
	public double getSuccessRateByAuthMethod(
			String authMethod) {

		long experimentCount =
				getExperimentCountByAuthMethod(
						authMethod);

		if (experimentCount == 0) {

			return 0.0;
		}

		long successCount =
				getSuccessCountByAuthMethod(
						authMethod);

		return ((double) successCount
				/ experimentCount) * 100.0;
	}

	/**
	 * 認証方式別平均攻撃試行回数
	 */
	public double getAverageAttemptCountByAuthMethod(
			String authMethod) {

		List<ExperimentResult> results =
				getResultsByAuthMethod(
						authMethod);

		if (results.isEmpty()) {

			return 0.0;
		}

		long total =
				results.stream()
				.mapToLong(
						ExperimentResult::getAttemptCount)
				.sum();

		return (double) total
				/ results.size();
	}

	/**
	 * 成功時攻撃時間合計
	 *
	 * 単位：ms
	 */
	public long getSuccessAttackTimeTotalByAuthMethod(
			String authMethod) {

		return getResultsByAuthMethod(authMethod)
				.stream()
				.filter(ExperimentResult::isSuccess)
				.mapToLong(
						ExperimentResult::getAttackTimeMs)
				.sum();
	}

	/**
	 * 成功時平均攻撃時間
	 *
	 * 単位：ms
	 */
	public double getAverageSuccessAttackTimeByAuthMethod(
			String authMethod) {

		List<ExperimentResult> successResults =
				getResultsByAuthMethod(
						authMethod)
				.stream()
				.filter(ExperimentResult::isSuccess)
				.toList();

		if (successResults.isEmpty()) {

			return 0.0;
		}

		long total =
				successResults.stream()
				.mapToLong(
						ExperimentResult::getAttackTimeMs)
				.sum();

		return (double) total
				/ successResults.size();
	}

	// =========================================================
	// 時間表示変換
	// =========================================================

	/**
	 * ミリ秒を
	 *
	 * 00h 00m 00s
	 *
	 * の形式へ変換する。
	 *
	 * 例：
	 * 19776
	 * ↓
	 * 00h 00m 19s
	 */
	public String formatDuration(
			long milliseconds) {

		if (milliseconds < 0) {

			milliseconds = 0;
		}

		long totalSeconds =
				milliseconds / 1000;

		long hours =
				totalSeconds / 3600;

		long minutes =
				(totalSeconds % 3600) / 60;

		long seconds =
				totalSeconds % 60;

		return String.format(
				"%02dh %02dm %02ds",
				hours,
				minutes,
				seconds);
	}

	/**
	 * double型のミリ秒を
	 *
	 * 00h 00m 00s
	 *
	 * に変換する。
	 *
	 * 平均攻撃時間用。
	 */
	public String formatDuration(
			double milliseconds) {

		if (milliseconds < 0) {

			milliseconds = 0;
		}

		long roundedMilliseconds =
				Math.round(milliseconds);

		return formatDuration(
				roundedMilliseconds);
	}

	// =========================================================
	// 認証方式別
	// 成功時攻撃時間合計（h m s）
	// =========================================================

	public String getSuccessAttackTimeTotalFormattedByAuthMethod(
			String authMethod) {

		return formatDuration(
				getSuccessAttackTimeTotalByAuthMethod(
						authMethod));
	}

	// =========================================================
	// 認証方式別
	// 成功時平均攻撃時間（h m s）
	// =========================================================

	public String getAverageSuccessAttackTimeFormattedByAuthMethod(
			String authMethod) {

		return formatDuration(
				getAverageSuccessAttackTimeByAuthMethod(
						authMethod));
	}

	// =========================================================
	// 実験結果削除
	// =========================================================

	@Transactional
	public void deleteResults(
			List<Long> ids) {

		if (ids == null
				|| ids.isEmpty()) {

			return;
		}

		experimentResultRepository.deleteAllByIdInBatch(
				ids);

		experimentResultRepository.flush();

		entityManager.flush();

		resequenceIds();
	}

	// =========================================================
	// 全結果削除
	// =========================================================

	@Transactional
	public void clearResults() {

		experimentResultRepository.deleteAll();

		experimentResultRepository.flush();

		entityManager.flush();

		entityManager.createNativeQuery(
				"ALTER TABLE experiment_results "
						+ "AUTO_INCREMENT = 1")
		.executeUpdate();

		entityManager.clear();
	}

	// =========================================================
	// ID再採番
	// =========================================================

	private void resequenceIds() {

		List<ExperimentResult> results =
				experimentResultRepository
				.findAllByOrderByIdAsc();

		int count =
				results.size();

		// -----------------------------------------------------
		// 結果が0件の場合
		// -----------------------------------------------------

		if (count == 0) {

			entityManager.createNativeQuery(
					"ALTER TABLE experiment_results "
							+ "AUTO_INCREMENT = 1")
			.executeUpdate();

			entityManager.clear();

			return;
		}

		entityManager.flush();

		// -----------------------------------------------------
		// 既存IDを一時的に負数へ変更
		// -----------------------------------------------------

		entityManager.createNativeQuery(
				"UPDATE experiment_results "
						+ "SET id = -id "
						+ "WHERE id > 0")
		.executeUpdate();

		// -----------------------------------------------------
		// 1から連番に変更
		// -----------------------------------------------------

		int newId = 1;

		for (ExperimentResult result
				: results) {

			Long oldId =
					result.getId();

			if (oldId == null) {

				continue;
			}

			entityManager.createNativeQuery(
					"UPDATE experiment_results "
							+ "SET id = :newId "
							+ "WHERE id = :oldId")
			.setParameter(
					"newId",
					newId)
			.setParameter(
					"oldId",
					-oldId)
			.executeUpdate();

			newId++;
		}

		// -----------------------------------------------------
		// AUTO_INCREMENTを設定
		// -----------------------------------------------------

		entityManager.createNativeQuery(
				"ALTER TABLE experiment_results "
						+ "AUTO_INCREMENT = "
						+ (count + 1))
		.executeUpdate();

		entityManager.clear();
	}
}