import fitz  # PyMuPDF
import os

def main():
	print('This app converts pdf to txt')
	input_file = input('File to convert->')
	output_file= input('Export path    ->')
	
	pdf_to_text_fitz(input_file, output_file)
	os.system('pause')
	
def pdf_to_text_fitz(pdf_path: str, txt_path:str):
	"""
	Извлекает текст из PDF с помощью PyMuPDF.
	Сохраняет хорошее форматирование и поддерживает многие типы PDF.
	"""
	try:
		doc = fitz.open(pdf_path)
		text = ""
		
		for page_num in range(len(doc)):
			page = doc.load_page(page_num)  # Получаем страницу
			text += page.get_text() + "\n\n"  # Извлекаем текст
		
		# Сохраняем в файл
		with open(txt_path, "w", encoding="utf-8") as txt_file:
			txt_file.write(text)
		
		print(f"Текст успешно извлечен и сохранен в: {txt_path}")
		print(f"Обработано страниц: {len(doc)}")
		doc.close()
		return True
	
	except Exception as e:
		print(f"Ошибка при обработке файла: {e}")
		return False
	
if __name__ == '__main__':
	main()

