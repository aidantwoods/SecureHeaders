<?php

$finder = (new \PhpCsFixer\Finder())
    ->in(__DIR__.'/src')
;

return (new \PhpCsFixer\Config())
    ->setRules([
        '@PER-CS' => true,
        '@PHP82Migration' => true,
        'array_syntax' => ['syntax' => 'short'],

        'braces_position' => [
            'control_structures_opening_brace' => 'next_line_unless_newline_at_signature_end',
            'anonymous_functions_opening_brace' => 'next_line_unless_newline_at_signature_end',
        ],
        'new_with_parentheses' => [
            'named_class' => false
        ],
        'list_syntax' => [
            'syntax' => 'long'
        ],
        'trailing_comma_in_multiline' => [
            'elements' => []
        ],
        'control_structure_continuation_position' => [
            'position' => 'next_line'
        ],
        'concat_space' => [
            'spacing' => 'none'
        ],
        'single_line_empty_body' => false,
        'not_operator_with_space' => true,
        'return_type_declaration' => [
            'space_before' => 'one',
        ],
    ])
    ->setFinder($finder)
;
