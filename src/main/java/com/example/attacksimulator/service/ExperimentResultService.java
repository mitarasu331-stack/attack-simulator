package com.example.attacksimulator.service;

import java.util.List;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.example.attacksimulator.model.ExperimentResult;
import com.example.attacksimulator.repository.ExperimentResultRepository;

@Service
public class ExperimentResultService {

	private final ExperimentResultRepository
	experimentResultRepository;

	@PersistenceContext
	private EntityManager entityManager;

	public ExperimentResultService(
			ExperimentResultRepository experimentResultRepository) {

		this.experimentResultRepository =
				experimentResultRepository;
	}

	// =========================================================
	// 実験結果登録
	// =========================================================

	/**
	 * 旧形式との互換用
	 *
	 * maxAttemptCountをintで受け取った場合
	 */
	@Transactional
	public ExperimentResult addResult(
			String authMethod,
			String authenticationConfiguration,
			int maxAttemptCount,
			int attemptCount,
			boolean success,
			String credential,
			long attackTimeMs) {

		return addResult(
				null,
				authMethod,
				authenticationConfiguration,
				String.valueOf(maxAttemptCount),
				attemptCount,
				success,
				credential,
				attackTimeMs);
	}

	/**
	 * usernameあり
	 *
	 * maxAttemptCountは文字列
	 *
	 * 例：
	 * 10000
	 * 3000 → 5000
	 * 3000 → 5000 → 2000
	 */
	@Transactional
	public ExperimentResult addResult(
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

		result.setId(null);

		return experimentResultRepository.save(result);
	}

	/**
	 * usernameなしの文字列版
	 */
	@Transactional
	public ExperimentResult addResult(
			String authMethod,
			String authenticationConfiguration,
			String maxAttemptCount,
			int attemptCount,
			boolean success,
			String credential,
			long attackTimeMs) {

		return addResult(
				null,
				authMethod,
				authenticationConfiguration,
				maxAttemptCount,
				attemptCount,
				success,
				credential,
				attackTimeMs);
	}

	// =========================================================
	// 実験番号
	// =========================================================

	public int getNextExperimentNumber() {

		long count =
				experimentResultRepository.count();

		return (int) count + 1;
	}

	// =========================================================
	// 結果取得
	// =========================================================

	public List<ExperimentResult> getAllResults() {

		return experimentResultRepository
				.findAllByOrderByIdAsc();
	}

	public ExperimentResult getLatestResult() {

		return experimentResultRepository
				.findTopByOrderByIdDesc()
				.orElse(null);
	}

	public List<ExperimentResult> getResultsByAuthMethod(
			String authMethod) {

		return experimentResultRepository
				.findByAuthMethodOrderByIdAsc(
						authMethod);
	}

	// =========================================================
	// 認証方式別集計
	// =========================================================

	public int getExperimentCountByAuthMethod(
			String authMethod) {

		return experimentResultRepository
				.findByAuthMethodOrderByIdAsc(
						authMethod)
				.size();
	}

	public int getSuccessCountByAuthMethod(
			String authMethod) {

		List<ExperimentResult> results =
				experimentResultRepository
				.findByAuthMethodOrderByIdAsc(
						authMethod);

		int count = 0;

		for (ExperimentResult result : results) {

			if (result.isSuccess()) {
				count++;
			}
		}

		return count;
	}

	public double getSuccessRateByAuthMethod(
			String authMethod) {

		List<ExperimentResult> results =
				experimentResultRepository
				.findByAuthMethodOrderByIdAsc(
						authMethod);

		if (results.isEmpty()) {
			return 0.0;
		}

		int successCount = 0;

		for (ExperimentResult result : results) {

			if (result.isSuccess()) {
				successCount++;
			}
		}

		return (double) successCount
				/ results.size()
				* 100.0;
	}

	public double getAverageAttemptCountByAuthMethod(
			String authMethod) {

		List<ExperimentResult> results =
				experimentResultRepository
				.findByAuthMethodOrderByIdAsc(
						authMethod);

		if (results.isEmpty()) {
			return 0.0;
		}

		long total = 0;

		for (ExperimentResult result : results) {

			total += result.getAttemptCount();
		}

		return (double) total
				/ results.size();
	}

	public long getSuccessAttackTimeTotalByAuthMethod(
			String authMethod) {

		List<ExperimentResult> results =
				experimentResultRepository
				.findByAuthMethodOrderByIdAsc(
						authMethod);

		long total = 0;

		for (ExperimentResult result : results) {

			if (result.isSuccess()) {
				total += result.getAttackTimeMs();
			}
		}

		return total;
	}

	public double getAverageSuccessAttackTimeByAuthMethod(
			String authMethod) {

		List<ExperimentResult> results =
				experimentResultRepository
				.findByAuthMethodOrderByIdAsc(
						authMethod);

		long total = 0;

		int successCount = 0;

		for (ExperimentResult result : results) {

			if (result.isSuccess()) {

				total += result.getAttackTimeMs();

				successCount++;
			}
		}

		if (successCount == 0) {
			return 0.0;
		}

		return (double) total
				/ successCount;
	}

	// =========================================================
	// 全体集計
	// =========================================================

	public int getTotalExperimentCount() {

		return (int)
				experimentResultRepository.count();
	}

	public long getTotalAttemptCount() {

		List<ExperimentResult> results =
				experimentResultRepository
				.findAllByOrderByIdAsc();

		long total = 0;

		for (ExperimentResult result : results) {

			total += result.getAttemptCount();
		}

		return total;
	}

	public double getAverageAttemptCount() {

		int experimentCount =
				getTotalExperimentCount();

		if (experimentCount == 0) {
			return 0.0;
		}

		long totalAttemptCount =
				getTotalAttemptCount();

		return (double) totalAttemptCount
				/ experimentCount;
	}

	// =========================================================
	// 選択した結果を削除
	// =========================================================

	@Transactional
	public void deleteResults(
			List<Long> ids) {

		if (ids == null
				|| ids.isEmpty()) {

			return;
		}

		experimentResultRepository
		.deleteAllByIdInBatch(ids);

		experimentResultRepository.flush();

		// JPAの変更を確定させてから
		// IDを振り直す
		entityManager.flush();

		resequenceIds();
	}

	// =========================================================
	// 全結果削除
	// =========================================================

	@Transactional
	public void clearResults() {

		experimentResultRepository
		.deleteAllInBatch();

		experimentResultRepository.flush();

		entityManager.flush();

		// AUTO_INCREMENTを1に戻す
		entityManager
		.createNativeQuery(
				"ALTER TABLE experiment_results "
						+ "AUTO_INCREMENT = 1")
		.executeUpdate();

		entityManager.clear();
	}

	// =========================================================
	// ID振り直し
	// =========================================================

	/**
	 * 削除後のIDを
	 *
	 * 1
	 * 2
	 * 3
	 * ...
	 *
	 * の連番に戻す。
	 *
	 * 例：
	 *
	 * 削除前
	 * 1
	 * 2
	 * 3
	 *
	 * 2を削除
	 *
	 * 1
	 * 3
	 *
	 * ↓
	 *
	 * 1
	 * 2
	 */
	private void resequenceIds() {

		List<ExperimentResult> results =
				experimentResultRepository
				.findAllByOrderByIdAsc();

		int count =
				results.size();

		// =====================================================
		// データが0件の場合
		// =====================================================

		if (count == 0) {

			entityManager
			.createNativeQuery(
					"ALTER TABLE experiment_results "
							+ "AUTO_INCREMENT = 1")
			.executeUpdate();

			entityManager.clear();

			return;
		}

		// =====================================================
		// JPAの変更を反映
		// =====================================================

		entityManager.flush();

		// =====================================================
		// 現在のIDを一時的に負数へ変更
		//
		// 例：
		// 1 → -1
		// 3 → -3
		//
		// これにより1,2,3への変更時に
		// 主キーが重複しないようにする。
		// =====================================================

		entityManager
		.createNativeQuery(
				"UPDATE experiment_results "
						+ "SET id = -id "
						+ "WHERE id > 0")
		.executeUpdate();

		// =====================================================
		// 1,2,3,... に振り直す
		// =====================================================

		int newId = 1;

		for (ExperimentResult result : results) {

			Long oldId =
					result.getId();

			if (oldId == null) {
				continue;
			}

			entityManager
			.createNativeQuery(
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

		// =====================================================
		// AUTO_INCREMENTを次の番号へ
		// =====================================================

		entityManager
		.createNativeQuery(
				"ALTER TABLE experiment_results "
						+ "AUTO_INCREMENT = "
						+ (count + 1))
		.executeUpdate();

		// =====================================================
		// JPAのキャッシュをクリア
		// =====================================================

		entityManager.clear();
	}
}