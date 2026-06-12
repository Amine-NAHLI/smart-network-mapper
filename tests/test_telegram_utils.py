import pytest
from reporter.telegram_utils import (
    TELEGRAM_SAFE_LENGTH,
    split_telegram_message,
    format_telegram_chunks,
)


class TestSplitTelegramMessage:
    def test_empty_text(self):
        assert split_telegram_message("") == []
        assert split_telegram_message(None) == []

    def test_short_text_unchanged(self):
        text = "Rapport court."
        assert split_telegram_message(text) == [text]

    def test_long_text_split_into_chunks(self):
        text = "A" * 5000
        chunks = split_telegram_message(text, max_length=1000)
        assert len(chunks) > 1
        assert all(len(c) <= 1000 for c in chunks)
        assert "".join(chunks) == text

    def test_prefers_paragraph_breaks(self):
        para = "Ligne de texte.\n\n"
        text = para * 200
        chunks = split_telegram_message(text, max_length=500)
        for chunk in chunks:
            assert len(chunk) <= 500

    def test_under_telegram_limit(self):
        text = "X" * TELEGRAM_SAFE_LENGTH
        chunks = split_telegram_message(text)
        assert len(chunks) == 1


class TestFormatTelegramChunks:
    def test_single_chunk_no_header(self):
        assert format_telegram_chunks(["hello"]) == ["hello"]

    def test_multiple_chunks_with_pagination(self):
        result = format_telegram_chunks(["part1", "part2"])
        assert len(result) == 2
        assert "1/2" in result[0]
        assert "2/2" in result[1]
