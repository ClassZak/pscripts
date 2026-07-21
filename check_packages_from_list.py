#!/usr/bin/env python3
"""
Скрипт для проверки пакетов из списка в проекте.
Запуск:
1. python3 check_packages_from_list.py "@accordproject/concerto-analysis (v3.24.1), @accordproject/concerto-linter (v3.24.1)"
2. Или: python3 check_packages_from_list.py --file infected_packages.txt
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path

def parse_package_spec(package_list_str):
	"""
	Парсит строку со списком пакетов.
	Поддерживает форматы:
	- "@accordproject/concerto-analysis (v3.24.1)"
	- "@accordproject/concerto-linter@3.24.1"
	- "@accordproject/concerto-analysis"
	Возвращает список кортежей (имя, версия или None).
	"""
	packages = []
	# Убираем переносы строк, разбиваем по запятым или переводам строк
	clean_str = package_list_str.replace('\n', ',').strip()
	items = re.split(r',|\n', clean_str)
	
	for item in items:
		item = item.strip()
		if not item:
			continue
		
		# Пытаемся извлечь имя и версию
		version = None
		name = item
		
		# Формат: "имя (vверсия)"
		match = re.match(r'(.+?)\s*\(v?([\d.]+)\)', item)
		if match:
			name, version = match.groups()
			name = name.strip()
		# Формат: "имя@версия"
		elif '@' in item and not item.startswith('@'):
			name, version = item.rsplit('@', 1)
		# Формат: "@scope/name@version"
		elif item.count('@') >= 2:
			parts = item.split('@')
			name = '@' + parts[1]
			version = parts[2] if len(parts) > 2 else None
		
		packages.append((name, version))
	
	return packages

def check_package_in_project(package_name, version=None):
	"""
	Проверяет наличие пакета в проекте.
	Возвращает словарь с результатами проверки в разных местах.
	"""
	results = {
		'package_name': package_name,
		'specified_version': version,
		'in_package_json': False,
		'in_package_lock': False,
		'in_node_modules': False,
		'found_versions': []
	}
	
	current_dir = Path.cwd()
	
	# 1. Проверка package.json
	package_json_path = current_dir / 'package.json'
	if package_json_path.exists():
		try:
			with open(package_json_path, 'r') as f:
				data = json.load(f)
			for dep_type in ['dependencies', 'devDependencies', 'peerDependencies']:
				if dep_type in data and package_name in data[dep_type]:
					results['in_package_json'] = True
					results['found_versions'].append(f"{data[dep_type][package_name]} ({dep_type})")
		except (json.JSONDecodeError, KeyError):
			pass
	
	# 2. Проверка package-lock.json
	package_lock_path = current_dir / 'package-lock.json'
	if package_lock_path.exists():
		try:
			with open(package_lock_path, 'r') as f:
				data = json.load(f)
			
			# Проверяем в dependencies (npm v6) и packages (npm v7+)
			found_lock_version = None
			
			# Для npm v7+ структура
			if 'packages' in data:
				pkg_key = f"node_modules/{package_name}"
				if pkg_key in data['packages']:
					found_lock_version = data['packages'][pkg_key].get('version')
				# Также проверяем корневой пакет
				if package_name in data['packages']:
					found_lock_version = data['packages'][package_name].get('version')
			
			# Для npm v6 структура
			elif 'dependencies' in data:
				def search_in_deps(deps, pkg_name):
					if pkg_name in deps:
						return deps[pkg_name].get('version')
					for dep in deps.values():
						if 'dependencies' in dep:
							found = search_in_deps(dep['dependencies'], pkg_name)
							if found:
								return found
					return None
				
				found_lock_version = search_in_deps(data['dependencies'], package_name)
			
			if found_lock_version:
				results['in_package_lock'] = True
				results['found_versions'].append(f"{found_lock_version} (package-lock)")
		except (json.JSONDecodeError, KeyError):
			pass
	
	# 3. Проверка node_modules (физическое наличие)
	node_modules_path = current_dir / 'node_modules'
	if node_modules_path.exists():
		# Разбираем scope пакеты типа @scope/name
		if package_name.startswith('@'):
			scope, pkg = package_name.split('/')
			pkg_dir = node_modules_path / scope / pkg
		else:
			pkg_dir = node_modules_path / package_name
		
		if pkg_dir.exists() and pkg_dir.is_dir():
			results['in_node_modules'] = True
			
			# Пытаемся прочитать версию из package.json пакета
			pkg_json = pkg_dir / 'package.json'
			if pkg_json.exists():
				try:
					with open(pkg_json, 'r') as f:
						pkg_data = json.load(f)
					pkg_version = pkg_data.get('version', 'unknown')
					results['found_versions'].append(f"{pkg_version} (node_modules)")
				except (json.JSONDecodeError, KeyError):
					pass
	
	return results

def main():
	parser = argparse.ArgumentParser(description='Проверка пакетов в проекте')
	group = parser.add_mutually_exclusive_group(required=True)
	group.add_argument('--list', type=str, help='Список пакетов в кавычках')
	group.add_argument('--file', type=str, help='Файл со списком пакетов')
	
	args = parser.parse_args()
	
	# Получаем список пакетов
	if args.list:
		package_list_str = args.list
	else:
		try:
			with open(args.file, 'r') as f:
				package_list_str = f.read()
		except FileNotFoundError:
			print(f"Файл {args.file} не найден")
			sys.exit(1)
	
	# Парсим список пакетов
	packages = parse_package_spec(package_list_str)
	
	if not packages:
		print("Не удалось распарсить список пакетов")
		sys.exit(1)
	
	print(f"🔍 Проверка {len(packages)} пакетов в проекте...\n")
	
	found_packages = []
	
	for package_name, version in packages:
		results = check_package_in_project(package_name, version)
		
		if any([results['in_package_json'], results['in_package_lock'], results['in_node_modules']]):
			found_packages.append(results)
			
			print(f"⚠️  {package_name}")
			if version:
				print(f"   Искомая версия: {version}")
			
			if results['found_versions']:
				print(f"   Найдена версия: {', '.join(results['found_versions'])}")
			
			locations = []
			if results['in_package_json']:
				locations.append("package.json")
			if results['in_package_lock']:
				locations.append("package-lock.json")
			if results['in_node_modules']:
				locations.append("node_modules")
			
			print(f"   Расположение: {', '.join(locations)}")
			print()
	
	# Сводка
	print("=" * 50)
	if found_packages:
		print(f"🚨 Найдено подозрительных пакетов: {len(found_packages)}")
		print("\nРекомендуемые действия:")
		print("1. Немедленно удалите эти пакеты:")
		for pkg in found_packages:
			print(f"   npm uninstall {pkg['package_name']}")
		print("2. Проверьте скрипты postinstall в package.json")
		print("3. Запустите npm audit для проверки других уязвимостей")
		print("4. Замените секретные токены (GitHub, npm, CI/CD)")
	else:
		print("✅ Указанные пакеты не найдены в проекте.")
		print("   Для дополнительной проверки выполните:")
		print("   1. npm audit - проверка известных уязвимостей")
		print("   2. Проверьте node_modules на наличие bundle.js ~3МБ")

if __name__ == '__main__':
	main()
