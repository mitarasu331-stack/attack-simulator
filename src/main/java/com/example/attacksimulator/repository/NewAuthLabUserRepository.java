package com.example.attacksimulator.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import com.example.attacksimulator.model.NewAuthLabUser;

@Repository
public class NewAuthLabUserRepository {

	private final JdbcTemplate jdbcTemplate;

	public NewAuthLabUserRepository(
			@Qualifier("newAuthLabJdbcTemplate")
			JdbcTemplate jdbcTemplate) {

		this.jdbcTemplate = jdbcTemplate;
	}

	/**
	 * usersテーブルから全ユーザーの
	 * usernameを取得する
	 */
	public List<String> findAllUsernames() {

		String sql =
				"SELECT username "
						+ "FROM users "
						+ "WHERE username IS NOT NULL "
						+ "ORDER BY username ASC";

		return jdbcTemplate.query(
				sql,
				(resultSet, rowNum) ->
				resultSet.getString("username"));
	}

	/**
	 * usernameを指定して、
	 * ユーザー情報を取得する
	 *
	 * password / password2 / password3 は
	 * BCryptハッシュ
	 *
	 * emailも取得する
	 */
	public Optional<NewAuthLabUser> findByUsername(
			String username) {

		String sql =
				"SELECT username, "
						+ "password, "
						+ "password2, "
						+ "password3, "
						+ "email "
						+ "FROM users "
						+ "WHERE username = ?";

		List<NewAuthLabUser> users =
				jdbcTemplate.query(
						sql,
						(resultSet, rowNum) ->
						new NewAuthLabUser(
								resultSet.getString(
										"username"),
								resultSet.getString(
										"password"),
								resultSet.getString(
										"password2"),
								resultSet.getString(
										"password3"),
								resultSet.getString(
										"email")),
						username);

		if (users.isEmpty()) {
			return Optional.empty();
		}

		return Optional.of(users.get(0));
	}
}